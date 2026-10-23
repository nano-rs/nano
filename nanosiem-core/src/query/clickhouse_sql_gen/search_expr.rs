// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search expression → WHERE clause generation
//!
//! Converts `SearchExpr` AST nodes into ClickHouse WHERE clause SQL,
//! handling UDM fields, JSON metadata fields, wildcards, regex, and
//! case-insensitive matching.

use super::eval_functions::{eval_expression_to_sql, guarded_ip_predicate, typed_eval_expression_to_sql};
use super::helpers::*;
use super::{ClickHouseSqlGenerator, SUBSEARCH_RESULT_LIMIT};
use crate::query::ast::*;
use crate::query::sql_gen::SqlGenError;

/// Observable LOGICAL UDM field names compared RAW (`<col> = '<lowered>'`) for
/// the `ioc` term (NAN-1580). These resolve (per the active schema profile) to a
/// physical column that is ingest-lowercased, so the whole-value bloom on the raw
/// column prunes (CLAUDE.md QO rule #2). Under UDM the logical name IS the column
/// (`src_ip`/`dest_ip` are in `LOWERCASE_NORMALIZED_FIELDS`; `dvc_ip` is downcased
/// on the same lane). Under OCSF they resolve to the promoted, ingest-lowercased
/// OCSF columns (`src_endpoint.ip`, `dst_endpoint.ip`, …) via the profile's
/// `udm_column_sql`. The raw-vs-lower decision is attached to the LOGICAL
/// observable: IPs/host/mac are lowercase-normalized on both schemas.
pub(crate) const IOC_OBSERVABLE_RAW_COLUMNS: &[&str] = &["src_ip", "dest_ip", "dvc_ip"];

/// Observable LOGICAL UDM field names compared via `lower(<col>) = '<lowered>'`
/// for the `ioc` term (NAN-1580). Mixed-case stored history (vendor hashes,
/// urls/domains, DNS query + DNS answers, device host/mac, email parties, cve,
/// rule/signature ids, user ids). Under UDM each is served by a migration-132/145
/// `idx_*_lower` expression bloom or migration-119 text index. Under OCSF they
/// resolve to the promoted OCSF columns (`file.hashes.sha256`, the `*_unified`
/// class-split columns, …) via the profile; observables OCSF has no column for
/// resolve to `None` and are SKIPPED (no dead column → no CH error).
pub(crate) const IOC_OBSERVABLE_LOWER_COLUMNS: &[&str] = &[
    "file_hash",
    "process_hash",
    "url",
    "url_domain",
    "dest_host",
    "query",
    "user_id",
    "sender",
    "recipient",
    "sender_domain",
    "recipient_domain",
    "cve",
    "rule_id",
    "signature_id",
    "dvc",
    "dvc_mac",
    "dns_answers",
];

/// Canonical OCSF 1.9 observables searched by the schema-level `ioc` term.
///
/// These are event paths, not Nano serving aliases. Repeated hash/answer
/// objects are represented by their canonical `value`/`rdata` leaves and use
/// array membership semantics below. Keeping this list beside the legacy UDM
/// list makes the storage boundary explicit: the selected schema contributes
/// exactly one vocabulary.
const OCSF_1_9_IOC_RAW_COLUMNS: &[&str] = &["src_endpoint.ip", "dst_endpoint.ip"];

const OCSF_1_9_IOC_RAW_ARRAY_COLUMNS: &[&str] = &[
    "file.hashes.value",
    "process.file.hashes.value",
    "actor.process.file.hashes.value",
];

const OCSF_1_9_IOC_LOWER_COLUMNS: &[&str] = &[
    "http_request.url.url_string",
    "url.url_string",
    "http_request.url.hostname",
    "url.hostname",
    "query.hostname",
    // NAN-2361: a domain indicator also surfaces as the DESTINATION of a
    // connection (Sysmon EID 3 DestinationHostname, proxy/firewall egress
    // logs), not only as a URL host or DNS question. Without this a hunt for a
    // known-bad domain silently missed every network-connection sighting of
    // it — confirmed live: an ingested EID 3 to a ThreatFox domain returned
    // hits=0 while the same domain seen in a DNS query returned hits=1.
    "dst_endpoint.hostname",
    "user.uid",
    "user.name",
    "actor.user.uid",
    "actor.user.name",
    "email.from",
    "email.to",
    "vulnerabilities.cve.uid",
];

const OCSF_1_9_IOC_LOWER_ARRAY_COLUMNS: &[&str] = &["answers.rdata"];

/// A single resolved observable in the active storage vocabulary.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedObservable {
    /// Schema-native observable name used for UI attribution.
    pub logical: &'static str,
    /// Profile-resolved, properly-escaped physical column SQL (e.g.
    /// `` `src_endpoint.ip` `` under OCSF, `src_ip` under UDM).
    pub col_sql: String,
    /// `true` → compare RAW (`<col> = 'v'`); `false` → `lower(<col>) = 'v'`.
    pub raw: bool,
    /// Whether the physical leaf is an `Array(String)` and therefore needs
    /// membership rather than scalar comparison semantics.
    pub array: bool,
}

/// Strict OCSF uses canonical 1.9 paths directly. The temporary ClickHouse/UDM
/// profile keeps its historical mapping isolated behind `udm_column_sql`; those
/// aliases are never accepted by or emitted for the lake profile.
pub(crate) fn resolve_ioc_observables(
    profile: &dyn crate::schema::SchemaProfile,
) -> Vec<ResolvedObservable> {
    let mut out = Vec::new();
    let groups: &[(bool, bool, &[&str])] = if profile.uses_strict_canonical_fields() {
        &[
            (true, false, OCSF_1_9_IOC_RAW_COLUMNS),
            (true, true, OCSF_1_9_IOC_RAW_ARRAY_COLUMNS),
            (false, false, OCSF_1_9_IOC_LOWER_COLUMNS),
            (false, true, OCSF_1_9_IOC_LOWER_ARRAY_COLUMNS),
        ]
    } else {
        &[
            (true, false, IOC_OBSERVABLE_RAW_COLUMNS),
            (false, false, IOC_OBSERVABLE_LOWER_COLUMNS),
        ]
    };
    for &(raw, array, names) in groups {
        for &logical in names {
            let col_sql = if profile.uses_strict_canonical_fields() {
                profile
                    .is_known_field(logical)
                    .then(|| crate::query::escape_identifier(logical))
            } else {
                profile.udm_column_sql(logical)
            };
            if let Some(col_sql) = col_sql {
                out.push(ResolvedObservable {
                    logical,
                    col_sql,
                    raw,
                    array,
                });
            }
        }
    }
    out
}

/// Classify an indicator value into a coarse type (ip/hash/url/cve/user/domain).
/// Shared by the retro rollup and the general `ioc=` SQL gen (NAN-1589/1590).
/// Does `field = "<literal>"` expand to `exact OR FQDN-prefix`?
///
/// A dotless literal on a host-entity field is deliberately NOT an exact match:
/// `device.hostname="ws-fin-011"` also matches `ws-fin-011.corp.local`, because
/// sources disagree about whether they emit the short name or the FQDN.
///
/// NAN-2361: this is public and shared because a SECOND consumer has to agree
/// with it. The lake compiler emits candidate hints used to prune objects
/// before the SQL ever runs, and a hint must be a SUPERSET of the predicate it
/// accompanies. It was emitting an exact-value entity hint here, which is
/// strictly NARROWER than the expansion — so every object was pruned away and
/// short-hostname lookups returned zero rows on promoted data, while the same
/// query worked on the un-indexed hot tail. Any future consumer that has to
/// reason about this expansion must call this rather than restate the rule.
/// The field is CANONICALIZED first: `entity_type` is not alias-aware, so
/// asking it about a UDM alias (`dest_hostname`) returns `None` while its
/// canonical form (`dest_host`) returns `Host`. Without this, an alias and the
/// column it resolves to compile to different predicates — the alias silently
/// staying exact-match while the canonical name expands.
pub fn hostname_equality_expands(
    profile: &dyn crate::schema::SchemaProfile,
    field: &str,
    literal: &str,
) -> bool {
    if literal.contains('.') {
        return false;
    }
    let canonical = profile.canonicalize(field);
    profile.entity_type(canonical.as_ref()) == Some(crate::schema::EntityType::Host)
}

pub fn classify_indicator(value: &str) -> &'static str {
    let v = value.trim();
    if v.parse::<std::net::IpAddr>().is_ok() {
        return "ip";
    }
    let hexlen = v.len();
    if (hexlen == 32 || hexlen == 40 || hexlen == 64) && v.chars().all(|c| c.is_ascii_hexdigit()) {
        return "hash";
    }
    if v.starts_with("http://") || v.starts_with("https://") {
        return "url";
    }
    if v.to_lowercase().starts_with("cve-") {
        return "cve";
    }
    if v.contains('@') {
        return "user";
    }
    if v.contains('.') && !v.contains(' ') {
        return "domain";
    }
    "other"
}

/// LOGICAL UDM observable columns worth scanning for an indicator of the given
/// coarse type (from [`classify_indicator`]).
///
/// The IOC match OR-expands the indicator across the observable set. Scanning
/// columns that can't hold the indicator's type is pure waste: for an IP the
/// `lower(file_hash)`/`lower(url)`/… legs never match AND don't index-prune for
/// an IP value, so they force column scans (measured 8.1s vs 2.0s IP-only over
/// 24h on a 1.7B-row tenant — NAN-1589). Restricting to the type's columns turns
/// each leg back into a bloom-pruned read. An empty slice means "type unknown —
/// keep the full observable set" (the caller's safe fallback).
pub(crate) fn observable_logicals_for_type(indicator_type: &str) -> &'static [&'static str] {
    match indicator_type {
        "ip" => &[
            "src_ip",
            "dest_ip",
            "dvc_ip",
            "src_endpoint.ip",
            "dst_endpoint.ip",
        ],
        "hash" => &[
            "file_hash",
            "process_hash",
            "file.hashes.value",
            "process.file.hashes.value",
            "actor.process.file.hashes.value",
        ],
        // a domain can surface as a URL host, an email party domain, a DNS
        // query, or the DESTINATION of a network connection (NAN-2361 — the
        // egress case was missing, so proxy/firewall/Sysmon-EID-3 sightings of
        // a known-bad domain were invisible to IOC hunting).
        //
        // NOTE: matching on `dst_endpoint.hostname` is correct here and must
        // NOT be confused with using it as the sighting's ASSET identity —
        // on a row matched this way the destination hostname IS the indicator.
        // See `LAKE_RETRO_ASSET_FIELDS` (search/service/retro.rs), which
        // deliberately excludes it for exactly that reason.
        "domain" => &[
            "url_domain",
            "dest_host",
            "sender_domain",
            "recipient_domain",
            "query",
            "http_request.url.hostname",
            "url.hostname",
            "query.hostname",
            "dst_endpoint.hostname",
        ],
        "url" => &["url", "http_request.url.url_string", "url.url_string"],
        "cve" => &["cve", "vulnerabilities.cve.uid"],
        "user" => &[
            "user_id",
            "sender",
            "recipient",
            "user.uid",
            "user.name",
            "actor.user.uid",
            "actor.user.name",
            "email.from",
            "email.to",
        ],
        _ => &[],
    }
}

/// Restrict the resolved observable set to the columns relevant to the
/// indicators' types (union across all indicators). Falls back to the FULL set
/// when any indicator is of unknown type, when nothing is known, or when the
/// filter would leave zero columns — the match must never scan an empty
/// predicate (a false "0 hits"). For a single IP this collapses ~17 observable
/// legs to 3 (NAN-1589/1590).
pub(crate) fn scope_observables(
    all: &[ResolvedObservable],
    indicators: &[String],
) -> Vec<ResolvedObservable> {
    let mut wanted: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for ind in indicators {
        let logicals = observable_logicals_for_type(classify_indicator(ind));
        if logicals.is_empty() {
            return all.to_vec();
        }
        wanted.extend(logicals.iter().copied());
    }
    if wanted.is_empty() {
        return all.to_vec();
    }
    let scoped: Vec<ResolvedObservable> = all
        .iter()
        .filter(|o| wanted.contains(o.logical))
        .cloned()
        .collect();
    if scoped.is_empty() {
        all.to_vec()
    } else {
        scoped
    }
}

/// Build the `SELECT lower(key_value) FROM custom_enrichment_results …`
/// subquery that resolves a feed-sourced IOC indicator set (NAN-1580).
///
/// Live IOC rows only: `is_ioc = 1 AND expires_at > now()`. The feed `arg`
/// matches either the enrichment name (substring, case-insensitive) or a tag
/// (exact membership), so `threatfox("apt29")` finds rows tagged `apt29` or
/// whose feed name contains `apt29`. `lower(key_value)` aligns with the
/// `lower(col)` comparison legs and the raw ingest-lowercased columns.
pub(crate) fn ioc_feed_indicator_subquery(feed: &IocFeed, is_clustered: bool) -> String {
    let name = escape_string(&feed.name.to_lowercase());
    let arg = escape_string(&feed.arg.to_lowercase());
    let arg_raw = escape_string(&feed.arg);
    // Reads via the `_distributed` wrapper on clusters (custom_enrichment_results
    // is in DISTRIBUTED_TABLES — per-shard table + additive wrapper) so the IN
    // set is complete across shards; on single-node `.read()` returns the local
    // `nanosiem.custom_enrichment_results` → byte-identical. Dupes are harmless in
    // an IN-subquery, so no version-collapse is needed here.
    let table =
        crate::db::dual_pool::TableNames::new(is_clustered).read("custom_enrichment_results");
    format!(
        "SELECT lower(key_value) FROM {table} \
         WHERE is_ioc = 1 AND expires_at > now() \
         AND (lower(enrichment_name) LIKE '%{name}%' \
         OR lower(enrichment_name) LIKE '%{arg}%' OR has(tags, '{arg_raw}'))"
    )
}

/// Build optimized SQL for a regex match against a field expression.
///
/// Applies optimizations in priority order:
/// 1. Simple literal (no metacharacters) → hasToken() (already handled by extract_simple_regex_token)
/// 2. Anchored prefix `^literal.*` → startsWith(lower(field), 'literal')
/// 3. Anchored suffix `.*literal$` → endsWith(lower(field), '.exe')
/// 4. Pure literal alternation `(a|b|c)` → hasToken OR chain
/// 5. Bloom guard: longest literal → hasToken(field, 'token') AND match(field, pattern)
/// 6. Fallback: plain match(field, pattern)
///
/// `field_expr`: the SQL expression for the field (e.g., `"command_line"`, `toString(ext.foo)`)
/// `skip_tostring`: true when `field_expr` is a plain String column, so the
///   case-insensitive substring guard uses `lower(field_expr)` — which matches
///   the `lower(<col>)` text skip index (NAN-1247). false keeps
///   `lower(toString(field_expr))` for ext/JSON/numeric fields (NULL-safety /
///   coercion). Computed by the caller via `search_lowered`/
///   `is_plain_string_search_column`.
/// `negated`: true for NotRegex (inverts the result)
fn build_optimized_regex_sql(
    field_expr: &str,
    pattern: &str,
    skip_tostring: bool,
    negated: bool,
) -> String {
    let escaped = escape_regex_pattern(pattern);
    let ci_pattern = if escaped.starts_with("(?i)") {
        format!("'{}'", escaped)
    } else {
        format!("'(?i){}'", escaped)
    };

    // Try optimizations on the raw pattern (before escaping for SQL)
    if let Some(opt) = analyze_regex_for_optimization(pattern) {
        match opt {
            RegexOptimization::Prefix(prefix) => {
                let escaped_prefix = escape_string(&prefix);
                if negated {
                    // NAN-1640: no guard under negation — mirrors the BloomGuard
                    // arm below (NOT startsWith ≢ guard AND NOT startsWith; a
                    // guard ANDed under negation changes semantics).
                    return format!(
                        "NOT startsWith(lower({}), '{}')",
                        field_expr, escaped_prefix
                    );
                }
                let base = format!("startsWith(lower({}), '{}')", field_expr, escaped_prefix);
                // NAN-1640: no skip index serves startsWith — text-index analysis
                // yields `tokens: []` and the whole column is read (Saturn:
                // 19.97GiB read_bytes on a selective 24h hunt). AND an implied,
                // index-servable guard in front: startsWith(x, lit) ⇒
                // x iLike '%tok%' for any token of lit, so results are identical
                // while the `lower(col)` text index prunes granules
                // (19.97GiB → 25.71MiB read_bytes, 795x). Only when the target is
                // a plain String column (`skip_tostring` — the exact `lower(col)`
                // index expression; ext/JSON/CTE targets have no index to serve
                // the guard) and the literal yields a token passing the NAN-1416
                // bar (the token is pure ASCII-alnum → no LIKE escaping needed).
                if skip_tostring {
                    if let Some(token) = anchored_guard_token(&prefix) {
                        return format!("lower({}) iLike '%{}%' AND {}", field_expr, token, base);
                    }
                }
                return base;
            }
            RegexOptimization::Suffix(suffix) => {
                let escaped_suffix = escape_string(&suffix);
                if negated {
                    // NAN-1640: no guard under negation (see the Prefix arm).
                    return format!("NOT endsWith(lower({}), '{}')", field_expr, escaped_suffix);
                }
                let base = format!("endsWith(lower({}), '{}')", field_expr, escaped_suffix);
                // NAN-1640: same implied text-index guard as the Prefix arm —
                // endsWith(x, lit) ⇒ x iLike '%tok%' for any token of lit.
                if skip_tostring {
                    if let Some(token) = anchored_guard_token(&suffix) {
                        return format!("lower({}) iLike '%{}%' AND {}", field_expr, token, base);
                    }
                }
                return base;
            }
            RegexOptimization::LiteralAlternation(literals) => {
                // NAN-1026 Phase 2: each literal lowered to iLike instead of hasToken*.
                // iLike with splitByNonAlpha gives substring-correct matching and
                // CH 26.4's LIKE-via-dictionary-scan keeps it index-accelerated.
                let conditions: Vec<String> = literals
                    .iter()
                    .map(|lit| {
                        let escaped_lit = escape_string(&lit.to_lowercase());
                        let pattern = escape_like_pattern(&escaped_lit);
                        if skip_tostring {
                            format!("lower({}) iLike '%{}%'", field_expr, pattern)
                        } else {
                            format!("lower(toString({})) iLike '%{}%'", field_expr, pattern)
                        }
                    })
                    .collect();
                let joined = conditions.join(" OR ");
                return if negated {
                    format!("NOT ({})", joined)
                } else if conditions.len() > 1 {
                    format!("({})", joined)
                } else {
                    joined
                };
            }
            RegexOptimization::BloomGuard(token) => {
                // NAN-1026 Phase 2: the guard becomes iLike (substring-correct, index-
                // accelerated via splitByNonAlpha) instead of hasToken*. Granules where
                // the longest literal substring isn't present get pruned, then match()
                // verifies the full regex on survivors.
                let escaped_token = escape_string(&token.to_lowercase());
                let pattern = escape_like_pattern(&escaped_token);
                let guard = if skip_tostring {
                    format!("lower({}) iLike '%{}%'", field_expr, pattern)
                } else {
                    format!("lower(toString({})) iLike '%{}%'", field_expr, pattern)
                };
                // For negated: NOT (guard AND match) → can't short-circuit, just negate match.
                if negated {
                    return format!("match({}, {}) = 0", field_expr, ci_pattern);
                }
                return format!("{} AND match({}, {})", guard, field_expr, ci_pattern);
            }
        }
    }

    // No optimization possible — plain regex
    if negated {
        format!("match({}, {}) = 0", field_expr, ci_pattern)
    } else {
        format!("match({}, {})", field_expr, ci_pattern)
    }
}

/// Validate a CIDR literal without normalizing it. ClickHouse otherwise raises
/// a runtime error for malformed prefixes, turning a bad hunt into a 500.
fn validate_cidr_literal(cidr: &str) -> Result<(), SqlGenError> {
    let mut parts = cidr.split('/');
    let address = parts.next().unwrap_or_default();
    let prefix = parts.next().unwrap_or_default();
    if address.is_empty() || prefix.is_empty() || parts.next().is_some() {
        return Err(SqlGenError::InvalidQuery(format!(
            "invalid CIDR literal '{cidr}'"
        )));
    }

    let address = address
        .parse::<std::net::IpAddr>()
        .map_err(|_| SqlGenError::InvalidQuery(format!("invalid CIDR address in '{cidr}'")))?;
    if !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SqlGenError::InvalidQuery(format!(
            "invalid CIDR prefix in '{cidr}'"
        )));
    }
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| SqlGenError::InvalidQuery(format!("invalid CIDR prefix in '{cidr}'")))?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(SqlGenError::InvalidQuery(format!(
            "CIDR prefix /{prefix} is out of range for {address}"
        )));
    }

    Ok(())
}

/// Prevalence scalar value meaning "no artifact on this row" (NAN-1689).
const PREVALENCE_NA_SENTINEL: u16 = 65535;

/// Whether any IN-list value is written as a CIDR (`a.b.c.d/n`, `x::/n`).
fn list_has_cidr(values: &[Value]) -> bool {
    values.iter().any(|value| matches!(value, Value::String(text) if text.contains('/')))
}

/// NAN-4285: split an IN-list into exact values and validated CIDR literals.
/// `None` when the list holds no CIDR.
fn split_cidr_list(values: &[Value]) -> Result<Option<(Vec<Value>, Vec<String>)>, SqlGenError> {
    let mut exact = Vec::new();
    let mut cidrs = Vec::new();
    for value in values {
        match value {
            Value::String(text) if text.contains('/') => {
                validate_cidr_literal(text)?;
                cidrs.push(text.clone());
            }
            other => exact.push(other.clone()),
        }
    }
    Ok((!cidrs.is_empty()).then_some((exact, cidrs)))
}

/// Membership of `ip` in any of `cidrs`: false (never NULL, never an error)
/// for a missing or non-IP value. An IPv4 address tested against an IPv6
/// network (or the reverse) is simply not a member.
fn cidr_membership_sql(ip: &str, cidrs: &[String]) -> String {
    let legs = cidrs
        .iter()
        .map(|cidr| format!("isIPAddressInRange(toString({ip}), '{}')", escape_string(cidr)))
        .collect::<Vec<_>>();
    guarded_ip_predicate(ip, &legs.join(" OR "))
}

impl ClickHouseSqlGenerator {
    /// Whether `field` is an IP-valued security entity under the active schema.
    ///
    /// OCSF's UDM-compatible aliases (for example `src_ip`) resolve to a
    /// differently named promoted column (`src_endpoint.ip`), so checking only
    /// the token's direct metadata misses them. Inspect the resolved physical
    /// column as well as the logical token.
    fn field_is_ip(&self, field: &str) -> bool {
        use crate::schema::{EntityType, FieldResolution, FieldType};

        let is_ip = |name: &str| {
            self.profile.entity_type(name) == Some(EntityType::Ip)
                || self.profile.field_type(name) == Some(FieldType::IpAddress)
        };

        if is_ip(field) {
            return true;
        }

        match self.profile.resolve(field) {
            FieldResolution::ExplicitColumn(column) | FieldResolution::Alias(column) => {
                is_ip(&column)
            }
            _ => false,
        }
    }

    /// Lower Splunk-style IP-field CIDR equality to ClickHouse network
    /// membership. `None` means this comparison is not CIDR syntax.
    ///
    /// `field!=cidr` deliberately retains the non-empty guard outside the
    /// negation. Splunk's `!=` only matches events where the field exists,
    /// whereas outer `NOT field=cidr` negates the entire guarded equality and
    /// therefore also matches missing/empty fields.
    fn generate_cidr_equality_filter(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
    ) -> Result<Option<String>, SqlGenError> {
        if !matches!(op, Comparator::Eq | Comparator::Ne) || !self.field_is_ip(field) {
            return Ok(None);
        }

        let Value::String(cidr) = value else {
            return Ok(None);
        };
        if !cidr.contains('/') {
            return Ok(None);
        }

        // NAN-4285: the same guarded membership as an IN-list CIDR, so a
        // non-IP value in an IP field (a hostname) is a non-member instead
        // of a CANNOT_PARSE_TEXT error that fails the whole search.
        let field_expr = self.filter_field_expr(field, "String");
        self.cidr_in_list_predicate(
            field,
            &field_expr,
            std::slice::from_ref(value),
            *op == Comparator::Ne,
            |_| Ok("0".to_string()),
        )
    }

    /// NAN-4285: `ip IN (10.0.0.0/8, 8.8.8.8)` on an IP field. A CIDR in the
    /// list is network membership, as it is for `ip=10.0.0.0/8`; it used to
    /// reach the string IN-list (`ip IN ('10.0.0.0/8')`) and matched nothing,
    /// so `NOT IN` matched everything. `None` means the list holds no CIDR
    /// (or the field is not an IP field) and the plain IN-list applies.
    ///
    /// Exact addresses keep the bloom-prunable IN-list built by `exact`; the
    /// CIDRs share one guarded `isIPAddressInRange` OR chain. `NOT IN`
    /// matches events that carry the field with a value outside every entry,
    /// the same presence rule as `ip!=10.0.0.0/8`.
    fn cidr_in_list_predicate(
        &self,
        field: &str,
        field_expr: &str,
        values: &[Value],
        negated: bool,
        exact: impl FnOnce(&[Value]) -> Result<String, SqlGenError>,
    ) -> Result<Option<String>, SqlGenError> {
        if !self.field_is_ip(field) {
            return Ok(None);
        }
        let Some((addresses, cidrs)) = split_cidr_list(values)? else {
            return Ok(None);
        };
        let mut legs = Vec::new();
        if !addresses.is_empty() {
            legs.push(exact(&addresses)?);
        }
        legs.push(cidr_membership_sql(field_expr, &cidrs));
        let matched = if legs.len() == 1 {
            legs.remove(0)
        } else {
            format!("({})", legs.join(" OR "))
        };
        Ok(Some(if negated {
            format!("(length(toString({field_expr})) > 0 AND {})", null_safe_not(&matched))
        } else {
            matched
        }))
    }

    /// Whether `field` is numeric under the active profile OR is a numeric column
    /// of the active OTLP dataset (`duration_ns`, `value`, …) (NAN-1534). For the
    /// default logs dataset the dataset set is empty, so this is exactly
    /// `self.profile.is_numeric_field(field)` — byte-identical.
    pub(super) fn field_is_numeric(&self, field: &str) -> bool {
        self.profile.is_numeric_field(field)
            || self.is_dataset_numeric_column(super::normalize_field_name(field))
    }

    /// Resolved schema type of `field`: the logical type, else the type of the
    /// physical column it resolves to.
    pub(super) fn resolved_field_type(&self, field: &str) -> Option<crate::schema::FieldType> {
        self.profile
            .field_type(field)
            .or_else(|| match self.profile.resolve(field) {
                crate::schema::FieldResolution::ExplicitColumn(column) => {
                    self.profile.field_type(&column)
                }
                _ => None,
            })
    }

    /// True when `field` is a typed non-string scalar (number, bool, time, UUID).
    /// Comparing such a column with `''` makes ClickHouse parse `''` as the
    /// column type, which fails (`Code: 32 ... while converting '' to UInt16`).
    fn field_is_non_string_scalar(&self, field: &str) -> bool {
        use crate::schema::FieldType;
        self.field_is_numeric(field)
            || matches!(
                self.resolved_field_type(field),
                Some(
                    FieldType::Integer
                        | FieldType::Long
                        | FieldType::Float
                        | FieldType::Boolean
                        | FieldType::Timestamp
                        | FieldType::Uuid
                )
            )
    }

    /// `prevalence_*` scalars encode "no artifact on this row" as 65535
    /// (NAN-1689). Existence must treat that sentinel as absent.
    fn is_prevalence_sentinel_field(&self, field: &str) -> bool {
        super::normalize_field_name(field).starts_with("prevalence_")
            && self.field_is_non_string_scalar(field)
    }

    /// NAN-2707: the `field=*` existence predicate, typed to the column.
    ///
    /// String columns keep the non-NULL and non-empty test unchanged. A typed
    /// scalar compares its rendered form instead, because `numeric != ''` is a
    /// ClickHouse type error. On the lake that error came back as a
    /// 500 and was reported to the analyst as "search service unavailable".
    /// Prevalence scalars also exclude their N/A sentinel, so
    /// `prevalence_dest_ip=*` means "has a prevalence value".
    fn scalar_presence_sql(&self, field: &str, field_expr: &str) -> String {
        if self.is_prevalence_sentinel_field(field) {
            return format!(
                "({field_expr} IS NOT NULL AND {field_expr} != {PREVALENCE_NA_SENTINEL})"
            );
        }
        if self.field_is_non_string_scalar(field) {
            return format!("({field_expr} IS NOT NULL AND toString({field_expr}) != '')");
        }
        format!("({field_expr} IS NOT NULL AND {field_expr} != '')")
    }

    /// Whether the logical or resolved physical field is a real Boolean leaf.
    /// Strict OCSF lake `unmapped.*` types come from the immutable manifest, so
    /// quoted UI drilldown values such as `"true"` must not enter `lower(Bool)`.
    fn field_is_boolean(&self, field: &str) -> bool {
        if self.profile.field_type(field) == Some(crate::schema::FieldType::Boolean) {
            return true;
        }
        match self.profile.resolve(field) {
            crate::schema::FieldResolution::ExplicitColumn(column) => {
                self.profile.field_type(&column) == Some(crate::schema::FieldType::Boolean)
            }
            _ => false,
        }
    }

    /// True when `field` resolves to an `Array(T)` leaf.
    ///
    /// Every path under an OCSF list-of-struct is one — `enrichments.name`,
    /// `enrichments.data.host_count`, and 61 others in the live lake manifest,
    /// which types them `array` already. The schema knew; the codegen did not
    /// ask.
    pub(super) fn field_is_array(&self, field: &str) -> bool {
        profile_field_is_array(self.profile.as_ref(), field)
    }

    /// Membership comparison for an `Array(T)` leaf.
    ///
    /// A scalar comparison against an array stringifies the WHOLE array, so
    /// `lower(toString("enrichments.name")) = 'prevalence'` compares against
    /// `"['prevalence','abuse.ch']"` and matches nothing — while returning
    /// HTTP 200, which is indistinguishable from "no matches". Worse, the
    /// substring form accidentally *works*, so `like "%ioc%"` would also match
    /// an element named `not_ioc`.
    ///
    /// `Ne` is "no element matches" (`NOT arrayExists`), which keeps
    /// `a != "x"` complementary to `a = "x"` over the same rows.
    fn array_membership_sql(&self, field_expr: &str, sql_op: &str, value: &Value) -> String {
        // Lowercased for case-insensitive membership; escaped in both arms. The
        // non-string arm goes through `value_to_sql` first so Ip/Regex/Interval
        // render canonically, then has its quoting stripped since the needle is
        // re-quoted below.
        let needle = match value {
            Value::String(text) => escape_string(&text.to_ascii_lowercase()),
            // NAN-4283: `value_to_sql` renders a Bool as `1`/`0`, but
            // `toString` of a Bool or of the stored `"true"` text is `true`.
            // `| where enrichments.data.is_rare=true` matched nothing.
            Value::Bool(flag) => flag.to_string(),
            other => escape_string(&value_to_sql(other).trim_matches('\'').to_ascii_lowercase()),
        };
        let exists = format!("arrayExists(x -> lower(toString(x)) = '{needle}', {field_expr})");
        if sql_op.trim() == "!=" {
            format!("NOT {exists}")
        } else {
            exists
        }
    }

    /// Range comparison against an `Array(T)` leaf: does ANY element satisfy it.
    ///
    /// `enrichments.data.host_count <= 25` must mean "some enrichment on this row
    /// reports 25 hosts or fewer", not "the rendered array compares less than
    /// '25'". Elements that are NULL (an enrichment of a different kind that has
    /// no such field) simply fail the predicate rather than poisoning the row,
    /// which is what makes a mixed `enrichments[]` array queryable at all.
    fn array_range_sql(&self, field_expr: &str, sql_op: &str, value: &Value) -> String {
        // Route through the shared converter rather than Display: it is the only
        // thing that quotes/escapes every Value variant (Ip, Regex, Interval)
        // correctly. An earlier version escaped the String arm and fell back to
        // raw `to_string()` for the rest -- no live parser path reached it, but
        // "unreachable today" is a property of the parser, not a guarantee.
        let rhs = value_to_sql(value);
        format!("arrayExists(x -> x IS NOT NULL AND x {sql_op} {rhs}, {field_expr})")
    }

    fn boolean_comparison_sql(&self, field_expr: &str, sql_op: &str, value: &Value) -> String {
        match value {
            Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => format!("{field_expr} {sql_op} true"),
                "false" | "0" => format!("{field_expr} {sql_op} false"),
                other => format!(
                    "lower(toString({field_expr})) {sql_op} '{}'",
                    escape_string(other)
                ),
            },
            Value::Bool(value) => format!("{field_expr} {sql_op} {value}"),
            _ => format!("{field_expr} {sql_op} {}", value_to_sql(value)),
        }
    }

    /// True when `field` resolves to a plain String column — a UDM/OCSF promoted
    /// `ExplicitColumn` that is neither numeric nor UUID. For these, full-text
    /// substring search must use `lower(<col>)`, NOT `lower(toString(<col>))`:
    /// ClickHouse matches a text skip index by EXPRESSION, and the `toString`
    /// wrapper orphans the `lower(<col>)` index → full scan (NAN-1247). For a real
    /// String column `toString(col)` is a semantic no-op, so dropping it changes
    /// only the SQL form (and turns the index back on), never the result.
    fn is_plain_string_search_column(&self, field: &str) -> bool {
        matches!(
            self.profile.resolve(field),
            crate::schema::FieldResolution::ExplicitColumn(_)
        ) && !self.profile.is_numeric_field(field)
            && !self.field_is_boolean(field)
            && !self.profile.is_uuid_field(field)
    }

    /// True when a field on the spill/JSON path resolves to a plain non-null
    /// String column after all: the class-split unified column (NAN-1333) or a
    /// promoted `ExplicitColumn` whose schema type is String — under OCSF a
    /// UDM-named alias (`user`, `file_hash`, …) resolves to a DIFFERENT column
    /// name, so the type check must consult the RESOLVED column, not the nPL
    /// token (`is_numeric_field("src_port")` is false under OCSF even though it
    /// resolves to the numeric `src_endpoint.port`). For these targets the
    /// NAN-1161 `toString()` JSON-null guard is a pure pessimization: the
    /// column is non-Nullable (MATERIALIZED `''`), `toString` is a semantic
    /// no-op, and ClickHouse matches a skip index by EXPRESSION — the wrapper
    /// orphans every `lower(col)` text/bloom index → full scan (NAN-1381,
    /// root cause of NAN-1247). Always false under UDM on this path (unknown
    /// fields resolve to `Unknown` → ext-JSON access keeps the guard).
    fn resolves_to_plain_string_column(&self, field: &str) -> bool {
        if self.profile.class_split_column(field).is_some() {
            return true;
        }
        match self.profile.resolve(field) {
            crate::schema::FieldResolution::ExplicitColumn(col) => {
                self.profile.field_type(&col) == Some(crate::schema::FieldType::String)
            }
            _ => false,
        }
    }

    /// Lowercased, index-matchable expression for case-insensitive substring /
    /// full-text search on `field` (whose access SQL is `field_expr`). Plain
    /// String columns → `lower(field_expr)` (matches the `lower(col)` text index);
    /// ext/JSON/numeric/uuid → `lower(toString(field_expr))` (NULL-safety /
    /// coercion). `message` flows through the String-column branch, so it stays
    /// byte-identical (`lower(message)`).
    fn search_lowered(&self, field: &str, field_expr: &str) -> String {
        if self.is_plain_string_search_column(field) {
            format!("lower({})", field_expr)
        } else {
            format!("lower(toString({}))", field_expr)
        }
    }

    /// Whether `field`'s *resolved physical column* is lowercase-normalized at
    /// ingest, so an Eq string compare (Eq ONLY — see the NAN-1643 comments at
    /// the call sites; Ne keeps the `lower()` form) can skip the `lower()`
    /// wrapper and the raw-column bloom/set indexes engage. Judged on the resolved column, not
    /// the raw nPL token: under OCSF a UDM alias like `src_ip` resolves to the
    /// ingest-lowercased promoted column `src_endpoint.ip`, which a raw-token
    /// lookup misses. Pre-NAN-1412 the explicit-PREWHERE duplicate carried the
    /// raw-form equality (resolved inside `extract_prewhere_conditions`) and
    /// rescued the index; with the single WHERE this arm is the only emission,
    /// so the resolution must happen here (EXPLAIN-verified on local CH:
    /// `idx_src_endpoint_ip` 553→88 granules). Class-split concepts (OCSF
    /// host/user/process/url) compare on the `_unified` column — `resolve()`
    /// returns only the primary source column, so they are deliberately
    /// excluded and keep the `lower(...)` form their text index serves
    /// (NAN-1333). UDM resolution is the identity and its lowercased set
    /// carries both alias and target spellings → byte-identical there.
    fn is_resolved_lowercased_at_ingest(&self, field: &str) -> bool {
        if self.profile.class_split_value_sql(field).is_some() {
            return false;
        }
        match self.profile.resolve(field) {
            crate::schema::FieldResolution::ExplicitColumn(col)
            | crate::schema::FieldResolution::Alias(col) => {
                self.profile.is_lowercased_at_ingest(&col)
            }
            _ => self.profile.is_lowercased_at_ingest(field),
        }
    }

    /// The LHS of a case-insensitive string compare against a physical column,
    /// in the form the skip indexes match by EXPRESSION: the bare column when
    /// it is lowercase-normalized at ingest (raw bloom/set indexes + PK
    /// analysis engage), `lower(col)` otherwise (the migration-119 text
    /// indexes are built on `lower(col)`). Shared by every filter arm so the
    /// form selection can't drift per-arm again (NAN-1634).
    /// LHS of the dotless-hostname expansion legs: the shared
    /// [`Self::string_filter_lhs`] on profiles whose storage has no
    /// `lower(col)` index to serve them (the object lake, NAN-3154), and
    /// `lower(col)` on ClickHouse, where that text index serves both legs.
    fn host_prefix_lhs(&self, field: &str, column_expr: &str) -> String {
        if self.profile.lowercased_host_prefix_compares_raw() {
            self.string_filter_lhs(field, column_expr)
        } else {
            format!("lower({})", column_expr)
        }
    }

    fn string_filter_lhs(&self, field: &str, column_expr: &str) -> String {
        if self.is_resolved_lowercased_at_ingest(field) {
            column_expr.to_string()
        } else {
            format!("lower({})", column_expr)
        }
    }

    /// Whether `field` names a plain physical String column under identity
    /// resolution — the bare name IS the base-table column, with no value-pick
    /// (class-split), Map subscript, spill/JSON access, numeric/UUID/Timestamp
    /// typing, or upstream shadowing in the way. Only such a column may take
    /// the index-form compare (`col`/`lower(col)`) instead of a normalizing
    /// `toString(...)` wrap. OCSF UDM-aliases resolve to a *different* column
    /// name → excluded → emission there is byte-identical (NAN-1634).
    fn is_plain_string_physical_column(&self, field: &str) -> bool {
        if self.resolves_to_map_key(field)
            || self.profile.class_split_value_sql(field).is_some()
            || self.is_upstream_computed_field(field)
            || self.profile.is_uuid_field(field)
            || self.field_is_numeric(field)
        {
            return false;
        }
        matches!(
            self.profile.field_type(field),
            Some(crate::schema::FieldType::String | crate::schema::FieldType::IpAddress)
        ) && matches!(
            self.profile.resolve(field),
            crate::schema::FieldResolution::ExplicitColumn(col) if col == field
        )
    }

    /// [`is_plain_string_physical_column`] narrowed to a `| where` stage scope:
    /// additionally rejects aggregation references (`avg(bytes_out)`, NAN-1339
    /// `{func}_{field}` aliases) and any pipeline-computed name (eval/rex/stats
    /// output — NAN-1341/1557), whose values are NOT the ingest-normalized
    /// column values. Those keep the scope-relative `lower(toString(...))`
    /// wrap; a surviving base column takes the index form the predicate
    /// pushdown carries into the stage_0 read (NAN-1634: the wrap matched
    /// neither the raw blooms nor the `lower(col)` text indexes — measured
    /// 31.8x read_rows on `* | where src_ip="…"` at production scale).
    ///
    /// [`is_plain_string_physical_column`]: Self::is_plain_string_physical_column
    fn where_scope_physical_string_column(&self, field: &str) -> bool {
        !field.contains('(')
            && self.agg_reference_alias(field).is_none()
            && !self.is_computed_field(field)
            && self.is_plain_string_physical_column(field)
    }

    /// NAN-3041: the physical expression of a schema ALIAS referenced in a
    /// `| where` stage, or `None` to keep the bare stage-column reference.
    ///
    /// The search term resolves `user` / `src_ip` / `process_name` on the lean
    /// lake to their OCSF homes (`user` = `if("user.name" != '', "user.name",
    /// "actor.user.name")`), and so does `eval`. The `| where` arm used the bare
    /// name, so `… | where NOT user="x"` compiled to `lower(toString("user"))`
    /// — a column that does not exist in an OCSF part — and silently matched
    /// every row (NOT) or none. Resolve exactly like `eval` (`field_to_sql_expr`)
    /// whenever the name is not a pipeline-computed column (stats by-field,
    /// eval/rex output, …) and the schema maps it somewhere other than its own
    /// name. UDM columns resolve to themselves, so gen1 is byte-identical.
    fn where_scope_schema_alias_expr(&self, original: &str, field: &str) -> Option<String> {
        if self.is_computed_field(field)
            || self.is_computed_field(original)
            || self.is_upstream_computed_field(original)
            || self.agg_reference_alias(field).is_some()
            || !self.resolves_to_column(field)
        {
            return None;
        }
        let (resolved, _) = field_to_sql_expr(field, self);
        (resolved != escape_identifier(field)).then_some(resolved)
    }

    /// [`Self::field_is_array`] for a `| where` operand, which is only an
    /// `Array(T)` leaf when it still names the schema field.
    ///
    /// NAN-3848: a pipeline-computed name shadows any same-named schema
    /// alias, which is how `where_scope_schema_alias_expr` builds the column
    /// reference. The array test has to agree with it. Without that, the
    /// Cloud resources panel's `eval resource_id=mvindex(...) | where
    /// resource_id!=""` saw the OCSF alias `resource_id -> resources.uid`
    /// (Array) and emitted `NOT arrayExists(..., resource_id)` against the
    /// scalar String eval output. chDB rejects that ("arrayExists arg 2 must
    /// be Array, found String"), so `/api/search/cloud-events` returned 400 on
    /// every lean tenant.
    fn where_scope_field_is_array(&self, original: &str, field: &str) -> bool {
        if self.is_computed_field(field)
            || self.is_computed_field(original)
            || self.is_upstream_computed_field(original)
            || self.agg_reference_alias(field).is_some()
        {
            return false;
        }
        self.field_is_array(field)
    }

    /// NAN-4276: whether a `| where` operand is a String-valued column, so a
    /// numeric literal compared with it must be typed as text (the search-term
    /// path already does this via `value_to_sql_for_field`). Without it,
    /// `| where metadata.event_code=7` emitted `"metadata.event_code" = 7` and
    /// chDB/ClickHouse refused it ("No supertype for types String, UInt8").
    ///
    /// Schema names qualify by their column type. A name a prior stage
    /// computed qualifies only when that stage proved it String
    /// (`upstream_string_fields`: a by-field passing a String column
    /// through, an eval of a String expression). Aggregation outputs,
    /// `{func}_{field}` references and every other computed name keep the
    /// bare compare (`| stats count | where count > 10`). Numeric, boolean,
    /// time and UUID columns, arrays and Map attributes (handled by their own
    /// arms) are never text.
    pub(super) fn where_scope_text_operand(&self, original: &str, field: &str) -> bool {
        use crate::schema::FieldType;
        if field.contains('(') || self.agg_reference_alias(field).is_some() {
            return false;
        }
        // A name an earlier stage computed carries that stage's values: String
        // only when the stage proved it (a by-field passing a String column
        // through, an eval of a String expression). NAN-4276.
        if self.is_upstream_computed_field(original) || self.is_upstream_computed_field(field) {
            return self.is_upstream_string_field(original) || self.is_upstream_string_field(field);
        }
        if self.resolves_to_map_key(field)
            || self.field_is_non_string_scalar(field)
            || self.field_is_boolean(field)
            || self.where_scope_field_is_array(original, field)
        {
            return false;
        }
        self.profile.class_split_value_sql(field).is_some()
            || matches!(
                self.resolved_field_type(field),
                Some(FieldType::String | FieldType::IpAddress)
            )
            || is_text_column(field, self.profile.as_ref())
    }

    /// Generate SQL for a search expression (WHERE clause content)
    pub fn generate_search_expr(&self, expr: &SearchExpr) -> Result<String, SqlGenError> {
        match expr {
            SearchExpr::Keyword(kw) => {
                // Handle wildcard * as match-all
                if kw == "*" {
                    return Ok("1".to_string());
                }

                // Bare keyword → token search via hasAllTokens (posting-list lookup
                // on the splitByNonAlpha text index). NAN-1515: the prior
                // `lower(message) iLike '%kw%'` substring form extracts no index
                // tokens and degrades to a dictionary scan — 35–206s at Saturn
                // scale vs 0.16–0.5s here. Bare keywords are now token-AND searches
                // (Splunk parity); substring intent (CONTAINS / regex / `*kw*`)
                // keeps its iLike form in its own arm. See
                // `bare_keyword_predicate`. NAN-1555: the indexed text column is
                // profile-driven (`message` for logs, `span_name` for spans).
                // NAN-1828: OR-folded across every body column (OCSF adds
                // `raw_data`; single-column profiles are byte-identical).
                Ok(bare_keyword_predicate(
                    kw,
                    &self.profile.keyword_search_columns(),
                    self.keyword_term_adjacency,
                ))
            }
            SearchExpr::FieldFilter {
                field,
                op,
                value,
                rhs,
            } => self.generate_field_filter(field, op, value, *rhs),
            SearchExpr::FunctionFilter {
                function,
                op,
                value,
            } => {
                let func_sql = eval_expression_to_sql(self, function)?;
                let sql_op = comparator_to_sql(op);
                // Case-insensitive string comparison for Eq/Ne
                match (op, value) {
                    (Comparator::Eq | Comparator::Ne, Value::String(s)) => Ok(format!(
                        "lower({}) {} '{}'",
                        func_sql,
                        sql_op,
                        escape_string(&s.to_lowercase())
                    )),
                    _ => {
                        let value_sql = value_to_sql(value);
                        Ok(format!("{} {} {}", func_sql, sql_op, value_sql))
                    }
                }
            }
            SearchExpr::BooleanFunction(function) => {
                // Standalone boolean function predicate: isnull(user), like(field, pattern), etc.
                eval_expression_to_sql(self, function)
            }
            SearchExpr::EvalPredicate(expression) => typed_eval_expression_to_sql(self, expression),
            SearchExpr::FieldFunctionFilter {
                field,
                op,
                function,
            } => {
                // NAN-1634: the LHS previously resolved unconditionally via
                // `generate_json_extract(field, "String")` — a metadata-JSON
                // probe that is empty for every explicit column (`metadata`
                // never carries copies of promoted fields), so
                // `user=lower(dest_user)` degenerated to `'' = rhs` and
                // matched WRONG rows. Dispatch like `FieldFilter`: known /
                // class-split / Map-tail fields resolve to their physical
                // access; unknown fields keep the metadata-JSON fallback.
                let field = self.canonicalize_field(field);
                let func_sql = eval_expression_to_sql(self, function)?;
                let sql_op = comparator_to_sql(op);
                let is_resolvable = self.profile.is_known_field(field)
                    || self.profile.class_split_value_sql(field).is_some()
                    || self.resolves_to_map_key(field);
                if is_resolvable {
                    let field_expr = self.filter_field_expr(field, "String");
                    if self.field_is_numeric(field) {
                        // Never lower() a numeric column (CH Code 43); the
                        // function side stays as-is (numeric expression).
                        return Ok(format!("{} {} {}", field_expr, sql_op, func_sql));
                    }
                    if self.profile.is_uuid_field(field) {
                        // toString(UUID) is lowercase-canonical; keep the old
                        // code's lower() on the function side so an
                        // uppercase-producing RHS still matches.
                        return Ok(format!(
                            "toString({}) {} lower({})",
                            field_expr, sql_op, func_sql
                        ));
                    }
                    return match op {
                        // Raw LHS for Eq ONLY (see the where-pipe arm): a raw
                        // Ne flips invariant-violating rows from excluded to
                        // included for zero index gain.
                        Comparator::Eq => Ok(format!(
                            "{} = lower({})",
                            self.string_filter_lhs(field, &field_expr),
                            func_sql
                        )),
                        Comparator::Ne => {
                            Ok(format!("lower({}) != lower({})", field_expr, func_sql))
                        }
                        _ => Ok(format!("{} {} {}", field_expr, sql_op, func_sql)),
                    };
                }
                let field_sql = self.generate_json_extract(field, "String");
                // Case-insensitive comparison for Eq/Ne
                match op {
                    Comparator::Eq | Comparator::Ne => Ok(format!(
                        "lower({}) {} lower({})",
                        field_sql, sql_op, func_sql
                    )),
                    _ => Ok(format!("{} {} {}", field_sql, sql_op, func_sql)),
                }
            }
            SearchExpr::InList {
                field,
                values,
                negated,
            } => self.generate_in_list_filter(field, values, *negated),
            SearchExpr::And(..) => {
                // NAN-4289 (F26): flat like OR (NAN-3276). 250 pasted
                // `NOT f=v` terms nested past ClickHouse's parse depth (Code 306).
                let legs = and_chain_legs(expr)
                    .into_iter()
                    .map(|leg| self.generate_search_expr(leg))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(format!("({})", legs.join(" AND ")))
            }
            SearchExpr::Or(..) => {
                // NAN-3276: one flat `(a OR b OR …)` per OR chain, never one
                // parenthesised level per binary node. A generated predicate
                // over thousands of values nested `((((a OR b) OR c) …)` past
                // every SQL parser's depth limit (sqlparser's 50, ClickHouse's
                // `max_parser_depth`); the flat chain parses at constant depth.
                let legs = or_chain_legs(expr)
                    .into_iter()
                    .map(|leg| self.generate_search_expr(leg))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(format!("({})", legs.join(" OR ")))
            }
            SearchExpr::Not(inner) => {
                let inner_sql = self.generate_search_expr(inner)?;
                Ok(null_safe_not(&inner_sql))
            }
            SearchExpr::Group(inner) => {
                let inner_sql = self.generate_search_expr(inner)?;
                Ok(format!("({})", inner_sql))
            }
            SearchExpr::LiteralComparison { left, op, right } => {
                // Literal string comparison - e.g., "$user"="*"
                // These evaluate to a constant true/false at runtime
                // Use case-insensitive comparison for Eq/Ne with strings
                let op_sql = comparator_to_sql(op);
                match (op, right) {
                    (Comparator::Eq | Comparator::Ne, Value::String(s)) => Ok(format!(
                        "lower('{}') {} '{}'",
                        escape_string(left),
                        op_sql,
                        escape_string(&s.to_lowercase())
                    )),
                    _ => {
                        let left_sql = format!("'{}'", escape_string(left));
                        let right_sql = value_to_sql(right);
                        Ok(format!("{} {} {}", left_sql, op_sql, right_sql))
                    }
                }
            }
            SearchExpr::InSubsearch {
                field,
                subsearch,
                negated,
                subsearch_dataset,
            } => self.generate_in_subsearch_filter(field, subsearch, *negated, *subsearch_dataset),
            // NAN-1580: observable-anywhere IOC term. Expands literal indicator
            // values across the full UDM observable column set (per-column index-
            // prunable equality), and for feed-sourced terms resolves the
            // indicator set from `custom_enrichment_results` via an IN-subquery.
            SearchExpr::IocMatch {
                values,
                feed,
                lookup,
            } => self.generate_ioc_match_filter(values, feed.as_ref(), lookup.as_ref()),
        }
    }

    /// SQL for the `ioc` observable-anywhere term (NAN-1580).
    ///
    /// Builds an OR of per-observable-column IN-lists — ONE predicate per
    /// observable carrying all values (`col IN ('v1','v2',…)`), not value×column
    /// equalities. A lookup-sourced term can carry tens of thousands of values;
    /// the per-value expansion blew up to ~800k OR clauses. IN on an indexed
    /// column prunes via the bloom/skip index exactly like equality (NAN-1412 /
    /// migration-132 lower-blooms + migration-119 text indexes), so ClickHouse can
    /// still skip granules per leg while the clause count collapses to one per
    /// observable (NAN-1580 P1-f):
    ///
    /// * Ingest-lowercased columns (`src_ip`, `dest_ip`, `dvc_ip`) compare RAW
    ///   (`col IN ('<lowered>',…)`) so their whole-value bloom on the raw column
    ///   prunes (CLAUDE.md QO rule #2).
    /// * Mixed-case-history columns (hashes, url/domain, dns query, email, cve,
    ///   rule/signature ids, user_id) compare via `lower(col) IN ('<lowered>',…)`,
    ///   served by the migration-132 `idx_*_lower` expression blooms.
    ///
    /// For a feed-sourced term (`ioc in threatfox("apt29")`) the values list is
    /// empty and `feed` is set: each observable column is matched via an
    /// `IN (<feed indicator subquery>)` against `custom_enrichment_results`,
    /// filtered to live IOC rows whose feed name / tags match the arg. The
    /// service layer (`build_retro_view`) ALSO resolves the concrete indicator
    /// list for the summary/list rollups; this SQL keeps the standalone term
    /// (`ioc in feed(...)` with no `| retro`) self-contained.
    fn generate_ioc_match_filter(
        &self,
        values: &[Value],
        feed: Option<&IocFeed>,
        lookup: Option<&IocLookup>,
    ) -> Result<String, SqlGenError> {
        // Feed-sourced with no concrete values: match each observable column
        // against the feed's resolved indicator set.
        if values.is_empty() {
            return match (feed, lookup) {
                (Some(f), _) => Ok(self.ioc_feed_match_filter(f)),
                // A lookup source reaching SQL generation unresolved means the
                // service layer's pre-resolution (`resolve_ioc_lookup_sources`)
                // was skipped — and an EMPTY lookup also resolves to no values.
                // Either way it matches nothing rather than scanning everything.
                (None, Some(_)) => Ok("0".to_string()),
                // No values AND no feed/lookup — a malformed/empty term.
                (None, None) => Ok("0".to_string()),
            };
        }

        // Resolve observables in exactly one vocabulary: canonical OCSF 1.9 for
        // the lake, historical UDM only for the legacy ClickHouse profile.
        let observables = resolve_ioc_observables(self.profile.as_ref());

        // NAN-1590: type-scope to the columns the indicator types can actually
        // live in (ip → the 3 IP cols, etc). The full OR across ~17 columns
        // includes non-prunable `lower(text)` legs that force scans — ~4x slower
        // and, under the 10s ext-fields cap, a 500. Mixed/unknown types fall back
        // to the full set (never an empty predicate). Same lever as the retro
        // rollup; here it also speeds every normal `ioc=` search.
        let value_strs: Vec<String> = values
            .iter()
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect();
        let observables = scope_observables(&observables, &value_strs);

        // Build a single IN-list of all (lowercased, escaped) values and emit ONE
        // predicate per observable column (`col IN (…)` / `lower(col) IN (…)`)
        // rather than values×columns equalities. A lookup-sourced term can carry
        // tens of thousands of values; the per-value-per-column expansion blew up
        // to ~800k OR clauses. IN on an indexed column prunes via the bloom/skip
        // index exactly like equality, so this keeps pruning while collapsing the
        // clause count to one-per-observable.
        let in_list = values
            .iter()
            .map(|value| {
                let lowered = match value {
                    Value::String(s) => s.to_lowercase(),
                    other => other.to_string().to_lowercase(),
                };
                format!("'{}'", escape_string(&lowered))
            })
            .collect::<Vec<_>>()
            .join(", ");

        let mut clauses = Vec::new();
        for obs in &observables {
            if obs.array && obs.raw {
                clauses.push(format!(
                    "arrayExists(x -> ifNull(x, '') IN ({}), {})",
                    in_list, obs.col_sql
                ));
            } else if obs.array {
                clauses.push(format!(
                    "arrayExists(x -> lower(ifNull(x, '')) IN ({}), {})",
                    in_list, obs.col_sql
                ));
            } else if obs.raw {
                clauses.push(format!("{} IN ({})", obs.col_sql, in_list));
            } else {
                clauses.push(format!("lower({}) IN ({})", obs.col_sql, in_list));
            }
        }

        // No resolvable observable (degenerate profile) — never matches.
        if clauses.is_empty() {
            return Ok("0".to_string());
        }
        Ok(format!("({})", clauses.join(" OR ")))
    }

    /// Subquery-backed observable match for a feed-sourced IOC term (NAN-1580).
    /// Each observable column is compared against the indicator set pulled from
    /// `custom_enrichment_results` for the named feed (live IOC rows only).
    /// OCSF-aware: columns resolve per the active profile (NAN-1580).
    fn ioc_feed_match_filter(&self, feed: &IocFeed) -> String {
        // `self.is_clustered` (set from `DualPool::TableNames::is_clustered()` via
        // `with_cluster_routing`) routes the subquery source to the wrapper on
        // clusters; single-node emits the local table name unchanged.
        let subquery = ioc_feed_indicator_subquery(feed, self.is_clustered);
        let observables = resolve_ioc_observables(self.profile.as_ref());
        let mut clauses = Vec::new();
        for obs in &observables {
            if obs.array && obs.raw {
                clauses.push(format!(
                    "arrayExists(x -> ifNull(x, '') IN ({}), {})",
                    subquery, obs.col_sql
                ));
            } else if obs.array {
                clauses.push(format!(
                    "arrayExists(x -> lower(ifNull(x, '')) IN ({}), {})",
                    subquery, obs.col_sql
                ));
            } else if obs.raw {
                clauses.push(format!("{} IN ({})", obs.col_sql, subquery));
            } else {
                clauses.push(format!("lower({}) IN ({})", obs.col_sql, subquery));
            }
        }
        if clauses.is_empty() {
            return "0".to_string();
        }
        format!("({})", clauses.join(" OR "))
    }

    /// A protocol label also finds older parser output containing only its IANA id.
    fn protocol_name_filter(&self, field: &str, op: &Comparator, value: &Value) -> Result<Option<String>, SqlGenError> {
        if self.profile.id() != crate::schema::SchemaId::Ocsf
            || (field != "protocol" && self.profile.canonicalize(field).as_ref() != "connection_info.protocol_name")
            || !matches!(op, Comparator::Eq | Comparator::Ne)
        { return Ok(None); }
        let Value::String(label) = value else { return Ok(None); };
        if label.contains('*') || label.contains('?') { return Ok(None); }
        let name = self.filter_field_expr("connection_info.protocol_name", "String");
        let num = self.filter_field_expr("connection_info.protocol_num", "Int64");
        let Some(crate::schema::EnumIntMapping::Values(labels)) = self.profile.enum_int_mapping("connection_info.protocol_num") else {
            return Err(SqlGenError::InvalidQuery("Protocol number mapping is unavailable".into()));
        };
        let id = enum_values_literal_sql(field, labels, label)?;
        let matched = format!("(lower(ifNull({name}, '')) = '{}' OR (ifNull({name}, '') = '' AND {num} = {id}))", escape_string(&label.to_lowercase()));
        Ok(Some(if *op == Comparator::Ne { format!("NOT {matched}") } else { matched }))
    }

    /// Generate SQL for IN list filter (case-insensitive for strings)
    pub(super) fn generate_in_list_filter(
        &self,
        field: &str,
        values: &[Value],
        negated: bool,
    ) -> Result<String, SqlGenError> {
        if (field == "protocol" || self.profile.canonicalize(field).as_ref() == "connection_info.protocol_name")
            && self.profile.id() == crate::schema::SchemaId::Ocsf {
            let parts = values.iter().map(|value| self.generate_field_filter(field, &Comparator::Eq, value, RhsSyntax::Literal))
                .collect::<Result<Vec<_>, _>>()?;
            let matched = if parts.is_empty() { "0".into() } else { format!("({})", parts.join(" OR ")) };
            return Ok(if negated { format!("NOT {matched}") } else { matched });
        }
        if list_has_cidr(values) {
            let field_expr = self.filter_field_expr(field, "String");
            if let Some(sql) = self.cidr_in_list_predicate(field, &field_expr, values, negated, |exact| {
                self.generate_in_list_filter(field, exact, false)
            })? {
                return Ok(sql);
            }
        }
        let op = if negated { "NOT IN" } else { "IN" };

        // Lake hashes and other repeated OCSF leaves are arrays, including
        // class-spanning product aliases such as process_hash. IN is element
        // membership; lower(array) is neither valid SQL nor scalar equality.
        if self.profile.is_string_array_field(field) {
            let column = self.filter_field_expr(field, "String");
            // NAN-3276: ONE element test against the whole list (the same
            // lowered needles `array_membership_sql` compares), not one
            // `arrayExists` per value OR-ed together: a long list stays one
            // flat expression.
            let needles: Vec<_> = values
                .iter()
                .map(|value| match value {
                    Value::String(text) => {
                        format!("'{}'", escape_string(&text.to_ascii_lowercase()))
                    }
                    other => format!(
                        "'{}'",
                        escape_string(&value_to_sql(other).trim_matches('\'').to_ascii_lowercase())
                    ),
                })
                .collect();
            let matched = if needles.is_empty() {
                "0".to_string()
            } else {
                format!(
                    "arrayExists(x -> lower(toString(x)) IN ({}), {column})",
                    needles.join(", ")
                )
            };
            return Ok(if negated {
                format!("NOT {matched}")
            } else {
                matched
            });
        }

        // Check if all values are strings (for case-insensitive handling)
        let all_strings = values.iter().all(|v| matches!(v, Value::String(_)));

        // NAN-1321: OCSF class-split UDM aliases (`src_host`, `user`, …) are not
        // promoted columns, so `is_known_field` is false and they would fall to the
        // metadata-JSON branch below (`JSONExtractString(metadata, 'src_host')`) —
        // empty under OCSF. Route them through the column branch so the IN-list
        // matches the value-pick `if(...)` like the `=` filter does. UDM never
        // class-splits → gate unchanged → byte-identical.
        let is_class_split = self.profile.class_split_value_sql(field).is_some();
        // NAN-1382 (G6): a UDM verb-valued alias resolving to an enum-INT OCSF
        // column (`auth_result` → `status_id`) is neither a known field nor
        // class-split, so it fell to the metadata-JSON branch below
        // (`JSONExtractString(metadata, 'auth_result')` — silently empty under
        // OCSF). Route enum-mapped fields through the column branch and translate
        // the string verbs there. UDM has no enum-int columns → None → gate (and
        // everything below) byte-identical.
        let enum_mapping = self.profile.enum_int_mapping(field);
        // NAN-1555: an un-promoted span/metrics attribute (`http.method`) is not a
        // "known field" but resolves to the `Map` tail — route it through the
        // column branch (→ `filter_field_expr` → `attributes['http.method']`)
        // instead of the UDM `JSONExtractString(metadata, …)` spill branch below.
        // UDM/OCSF never yield `MapKey`, so the gate is byte-identical for them.
        if self.profile.is_known_field(field)
            || is_class_split
            || enum_mapping.is_some()
            || self.resolves_to_map_key(field)
        {
            // Determine the physical access expression via the active profile:
            // ExplicitColumn → escaped column, JsonPath → native `event` subcolumn
            // access (NAN-1426), Unknown → `ext.{field}` (UDM's spill). For OCSF a known field is always a
            // promoted ExplicitColumn, so this is byte-identical for UDM.
            // NAN-1321: class-split concepts resolve to the value-pick `if(...)` so
            // an IN-list filter matches the host/user/process wherever the class put
            // it (UDM unaffected → bare column).
            let field_expr = self.filter_field_expr(field, "String");

            // NAN-1382 (G6): enum-int targets translate string verbs before the
            // generic string/numeric arms (which would emit `lower(<int col>)` — a
            // CH type error — or the never-matching `0` fallback).
            if let Some(mapping) = enum_mapping {
                return match mapping {
                    crate::schema::EnumIntMapping::Values(labels) => {
                        // Fixed table: every verb maps to its id (numeric strings
                        // pass through; unknown labels fail loudly).
                        let values_sql: Result<Vec<String>, SqlGenError> = values
                            .iter()
                            .map(|v| match v {
                                Value::String(s) => enum_values_literal_sql(field, labels, s),
                                _ => Ok(value_to_sql(v)),
                            })
                            .collect();
                        Ok(format!(
                            "{} {} ({})",
                            field_expr,
                            op,
                            values_sql?.join(", ")
                        ))
                    }
                    crate::schema::EnumIntMapping::LabelColumn(sibling) => {
                        // Class-scoped enum: integer ids hit the int column, verbs
                        // hit the sibling label column. A mixed list ORs the two
                        // memberships (AND when negated — De Morgan).
                        let mut int_vals: Vec<String> = Vec::new();
                        let mut label_vals: Vec<String> = Vec::new();
                        for v in values {
                            match v {
                                // Parsed (not raw) so "+2"/"007" emit canonically.
                                Value::String(s) => match s.parse::<i64>() {
                                    Ok(id) => int_vals.push(id.to_string()),
                                    Err(_) => label_vals
                                        .push(format!("'{}'", escape_string(&s.to_lowercase()))),
                                },
                                _ => int_vals.push(value_to_sql(v)),
                            }
                        }
                        let mut parts: Vec<String> = Vec::new();
                        if !int_vals.is_empty() {
                            parts.push(format!("{} {} ({})", field_expr, op, int_vals.join(", ")));
                        }
                        if !label_vals.is_empty() {
                            parts.push(format!(
                                "lower({}) {} ({})",
                                escape_identifier(sibling),
                                op,
                                label_vals.join(", ")
                            ));
                        }
                        let joiner = if negated { " AND " } else { " OR " };
                        Ok(if parts.len() == 1 {
                            parts.remove(0)
                        } else {
                            format!("({})", parts.join(joiner))
                        })
                    }
                };
            }

            if self.profile.is_uuid_field(field) {
                // UUID fields: use toString() instead of lower()
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => format!("'{}'", escape_string(&s.to_lowercase())),
                        _ => value_to_sql_for_field(field, v, self.profile.as_ref()),
                    })
                    .collect();
                let values_list = values_sql.join(", ");
                Ok(format!("toString({}) {} ({})", field_expr, op, values_list))
            } else if self.field_is_numeric(field) {
                if self.profile.id() == crate::schema::SchemaId::Ocsf {
                    for value in values {
                        if let Value::String(label) = value {
                            if label.parse::<f64>().is_err() {
                                return Err(SqlGenError::InvalidQuery(format!("Cannot resolve label '{label}' for numeric OCSF field '{field}'; use an integer id")));
                            }
                        }
                    }
                }
                // Numeric fields: never apply lower() — convert string values to numbers
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => {
                            if s.parse::<i64>().is_ok() || s.parse::<f64>().is_ok() {
                                s.to_string()
                            } else {
                                // Non-numeric string — use 0 as fallback (will never match)
                                "0".to_string()
                            }
                        }
                        _ => value_to_sql_for_field(field, v, self.profile.as_ref()),
                    })
                    .collect();
                let values_list = values_sql.join(", ");
                Ok(format!("{} {} ({})", field_expr, op, values_list))
            } else if all_strings {
                // Case-insensitive membership. NAN-1634: mirror the Eq arm's
                // form selection — the literals are lowercased at emission, so
                // an ingest-lowercased column compares RAW and its bloom/set
                // index + PK analysis prune (unconditional `lower(field) IN`
                // measured 8.6x read_rows on a 7d two-IP hunt). Class-split
                // value-picks and mixed-case-history columns (dest_user,
                // hashes) resolve false and keep the `lower(...)` form.
                // Positive membership ONLY (same rule as the raw-Eq arms): a
                // raw NOT IN flips invariant-violating rows from excluded to
                // included, and no skip index prunes a negation anyway.
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => format!("'{}'", escape_string(&s.to_lowercase())),
                        _ => value_to_sql_for_field(field, v, self.profile.as_ref()),
                    })
                    .collect();
                let values_list = values_sql.join(", ");
                let lhs = if !negated {
                    self.string_filter_lhs(field, &field_expr)
                } else {
                    format!("lower({})", field_expr)
                };
                let membership = format!("{} {} ({})", lhs, op, values_list);

                // NAN-2361: `IN` must mean the same thing `=` does.
                //
                // A dotless literal on a host-entity field expands to
                // `= v OR startsWith(col, 'v.')` in the Eq arm, so short names
                // match FQDNs. The IN arm had no such expansion, which made
                // `host = "ws-fin-011"` and `host IN ("ws-fin-011")` two
                // different questions. The asset dossier builds its predicate
                // as `IN (...)`, so it kept splitting one host into two assets
                // long after the `=` path was fixed.
                //
                // Only the dotless literals get a prefix leg; FQDNs are already
                // exact. Negation is De Morgan's: NOT IN AND none-of-the-prefixes.
                let prefix_legs: Vec<String> = values
                    .iter()
                    .filter_map(|value| match value {
                        Value::String(text)
                            if hostname_equality_expands(self.profile.as_ref(), field, text) =>
                        {
                            // NAN-3154: positive legs follow the membership's
                            // own LHS (raw on ingest-lowercased columns); a
                            // negation keeps `lower()` like the NOT IN above.
                            Some(format!(
                                "{}startsWith({}, '{}.')",
                                if negated { "NOT " } else { "" },
                                if negated { format!("lower({})", field_expr) } else { self.host_prefix_lhs(field, &field_expr) },
                                escape_string(&text.to_lowercase())
                            ))
                        }
                        _ => None,
                    })
                    .collect();
                if prefix_legs.is_empty() {
                    return Ok(membership);
                }
                let joiner = if negated { " AND " } else { " OR " };
                Ok(format!(
                    "({}{}{})",
                    membership,
                    joiner,
                    prefix_legs.join(joiner)
                ))
            } else {
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| value_to_sql_for_field(field, v, self.profile.as_ref()))
                    .collect();
                let values_list = values_sql.join(", ");
                Ok(format!("{} {} ({})", field_expr, op, values_list))
            }
        } else {
            // For metadata fields, use JSONExtractString
            let json_extract = self.generate_json_extract(field, "String");

            if all_strings {
                // Case-insensitive
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => format!("'{}'", escape_string(&s.to_lowercase())),
                        _ => value_to_sql(v),
                    })
                    .collect();
                let values_list = values_sql.join(", ");
                Ok(format!("lower({}) {} ({})", json_extract, op, values_list))
            } else {
                let values_sql: Vec<String> = values.iter().map(value_to_sql).collect();
                let values_list = values_sql.join(", ");
                Ok(format!("{} {} ({})", json_extract, op, values_list))
            }
        }
    }

    /// Generate SQL for a field filter
    /// Resolve a `<field> = <other>` / `<field> != <other>` term into a
    /// field-to-field comparison, or refuse it as ambiguous (NAN-2378 /
    /// NAN-2380).
    ///
    /// The tokenizer used to throw away quotedness, so an unquoted RHS became a
    /// string literal for `=` / `!=` (only `>` `<` `>=` `<=` peeked for a bare
    /// field reference). `| where process.name != process.file.name` therefore
    /// asked "is process.name different from the seventeen-character text
    /// `process.file.name`" — true for every row ever ingested — and `=` asked
    /// the mirror question, false for every row. That is not a missing feature:
    /// it is the EXACT INVERSE of the intended predicate, returned with a
    /// plausible row count and no error. It silently destroys the whole
    /// "claims to be X but is actually Y" masquerading family (T1036.003).
    ///
    /// The reading is decided by [`classify_rhs`], which is also called by query
    /// validation; this method is the codegen backstop that covers every
    /// non-search lane (detection rules, materialized views, dashboards). It is
    /// the one place holding both the term and the active `SchemaProfile`, and
    /// it is shared by ClickHouse UDM, ClickHouse OCSF and the object lake.
    ///
    /// A resolved term is returned as the existing `FieldFunctionFilter` node —
    /// the same shape `first_seen > time_threshold` already produces — so
    /// column-to-column SQL is emitted by code that was already exercised.
    pub(crate) fn field_to_field_term(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
        rhs_syntax: RhsSyntax,
    ) -> Result<Option<SearchExpr>, SqlGenError> {
        match classify_rhs(self.profile.as_ref(), field, op, value, rhs_syntax) {
            RhsReading::Literal => Ok(None),
            RhsReading::FieldReference => {
                let Value::String(rhs) = value else {
                    unreachable!("classify_rhs only resolves a Value::String")
                };
                Ok(Some(SearchExpr::FieldFunctionFilter {
                    field: field.to_string(),
                    op: *op,
                    function: EvalExpression::Field(rhs.clone()),
                }))
            }
            RhsReading::Ambiguous => {
                let Value::String(rhs) = value else {
                    unreachable!("classify_rhs only flags a Value::String")
                };
                Err(SqlGenError::InvalidQuery(ambiguous_comparison_message(
                    field, op, rhs,
                )))
            }
        }
    }

    /// NAN-4286 (F30): the SQL literal for `time <op> <value>` (a search term
    /// or `| where`) when `field` is a Timestamp column. ClickHouse parses a String compared with
    /// DateTime64 in its basic format only, so `"2026-10-20T22:30:00Z"` was
    /// Code 53, `"2026-10-20 22:30"` Code 41, and an epoch number compared as
    /// raw DateTime64 ticks and silently matched nothing. Accept what the
    /// search API accepts for `time_range` (RFC3339 with `Z` or an offset), the
    /// same text without a zone (UTC), minute or date precision, and epoch
    /// seconds; refuse anything else with a message instead of a chDB error.
    fn time_literal_sql(
        &self,
        original_field: &str,
        field: &str,
        op: &Comparator,
        value: &Value,
    ) -> Result<Option<String>, SqlGenError> {
        if !matches!(
            op,
            Comparator::Eq
                | Comparator::Ne
                | Comparator::Gt
                | Comparator::Lt
                | Comparator::Gte
                | Comparator::Lte
        ) || self.is_upstream_computed_field(original_field)
            || self.agg_reference_alias(field).is_some()
            || !matches!(
                self.resolved_field_type(field),
                Some(crate::schema::FieldType::Timestamp)
            )
        {
            return Ok(None);
        }
        let instant = match value {
            Value::Number(seconds) if seconds.is_finite() => {
                return Ok(Some(format!("toDateTime64({seconds}, 3, 'UTC')")));
            }
            // Wildcards keep their existing text semantics.
            Value::String(text) if text.contains(['*', '?']) => return Ok(None),
            Value::String(text) => parse_time_literal(text).ok_or_else(|| {
                SqlGenError::InvalidQuery(format!(
                    "Cannot compare '{original_field}' with \"{text}\": write a time as RFC3339 \
                     (\"2026-10-20T22:30:00Z\" or with an offset), \"2026-10-20 22:30:00\" (UTC), \
                     or epoch seconds"
                ))
            })?,
            _ => return Ok(None),
        };
        Ok(Some(format!(
            "toDateTime64('{}', 3, 'UTC')",
            instant.format("%Y-%m-%d %H:%M:%S%.3f")
        )))
    }

    /// NAN-4286: a `| where` comparison whose bare RHS names a column the
    /// pipeline computed upstream (`| eval c=404 | where http_response.code=c`),
    /// or whose LHS is such a column and whose bare RHS is a schema path
    /// (`| where c=http_response.code`). The profile alone cannot see either
    /// shape, so `classify_rhs` read the RHS as the literal text `'c'` and the
    /// filter silently matched nothing. A name the analyst just defined in this
    /// pipeline is a column; a quoted RHS stays a literal.
    fn where_scope_computed_field_term(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
        rhs_syntax: RhsSyntax,
    ) -> Option<SearchExpr> {
        if !matches!(rhs_syntax, RhsSyntax::Bareword)
            || !matches!(
                op,
                Comparator::Eq
                    | Comparator::Ne
                    | Comparator::Gt
                    | Comparator::Lt
                    | Comparator::Gte
                    | Comparator::Lte
            )
        {
            return None;
        }
        let Value::String(rhs) = value else {
            return None;
        };
        if !is_bareword_identifier(rhs) {
            return None;
        }
        let rhs_is_column = self.is_upstream_computed_field(rhs)
            || (self.is_upstream_computed_field(field)
                && self.profile.is_known_field(rhs)
                && (is_dotted_schema_path(rhs) || self.profile.uses_strict_canonical_fields()));
        rhs_is_column.then(|| SearchExpr::FieldFunctionFilter {
            field: field.to_string(),
            op: *op,
            function: EvalExpression::Field(rhs.clone()),
        })
    }

    pub(super) fn generate_field_filter(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
        rhs_syntax: RhsSyntax,
    ) -> Result<String, SqlGenError> {
        // SECURITY: Validate field name format to prevent injection of function calls
        // (e.g., "version()" or "currentDatabase()") through field name positions.
        crate::query::validation::validate_field_name_format(field)
            .map_err(|e| SqlGenError::InvalidQuery(e.message))?;

        // Validate regex patterns before generating SQL
        if let Value::Regex(pattern) = value {
            validate_regex_pattern(pattern).map_err(|e| SqlGenError::InvalidQuery(e))?;
        }

        // NAN-2378/NAN-2380: `a = b` where `b` is a column, not a literal.
        if let Some(term) = self.field_to_field_term(field, op, value, rhs_syntax)? {
            return self.generate_search_expr(&term);
        }

        if let Some(sql) = self.protocol_name_filter(field, op, value)? { return Ok(sql); }
        // Normalize field name (apply aliases like sourcetype -> source_type).
        // NAN-1555: profile-aware so spans keep `service_name` (not the UDM
        // `cloud_service` alias); logs byte-identical via the free alias map.
        let field = self.canonicalize_field(field);

        // Splunk treats equality against CIDR notation as network membership
        // for IP fields. This must run before the known/JSON routing split so
        // OCSF UDM aliases receive the same behavior as native promoted fields.
        if let Some(sql) = self.generate_cidr_equality_filter(field, op, value)? {
            return Ok(sql);
        }

        // Check if it's a UDM field (direct column) or metadata field (JSON)
        if self.profile.is_known_field(field) {
            self.generate_udm_field_filter(field, op, value)
        } else {
            self.generate_json_field_filter(field, op, value)
        }
    }

    /// Generate SQL for a filter on an `Array(String)` column (`tags`, `*_tags`).
    ///
    /// Equality is element membership (`has`), which is index/short-circuit
    /// friendly; wildcards / contains / like / starts/ends / regex fall back to
    /// `arrayExists` over a per-element predicate. Values are lowercased to match
    /// the lowercase-canonical tag convention. Numeric comparators don't apply.
    fn generate_array_field_filter(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
    ) -> Result<String, SqlGenError> {
        let col = self.filter_field_expr(field, "String");

        // (per-element predicate over `x`, negate). Exact-equality short-circuits
        // to has() before this, since it's cheaper than arrayExists.
        let (elem, negate): (String, bool) = match (op, value) {
            // NAN-2361: `field=*` is an EXISTENCE test, not "match all rows".
            // It used to compile to the literal `1`, so `file.hashes.value=*`
            // became `WHERE 1` and returned every row in the window — measured
            // at 395 of 400 sampled rows carrying no hash at all. On an array
            // column, presence is a non-empty array.
            (Comparator::Eq, Value::String(s)) if s == "*" => {
                return Ok(format!("notEmpty({col})"))
            }
            (Comparator::Ne, Value::String(s)) if s == "*" => return Ok(format!("empty({col})")),
            (Comparator::Eq | Comparator::Ne, Value::String(s)) => {
                let negate = *op == Comparator::Ne;
                // Canonical repeated OCSF objects use an empty array for an
                // absent value. Treat `field=""` / `field!=""` as array
                // absence/presence, not membership of an empty string. The
                // latter incorrectly made `[] != ""` true.
                if s.is_empty() {
                    return Ok(if negate {
                        format!("notEmpty({})", col)
                    } else {
                        format!("empty({})", col)
                    });
                }
                if s.contains('*') || s.contains('?') {
                    let pattern = wildcard_to_like_pattern(&s.to_lowercase());
                    (format!("lower(x) iLike '{}'", pattern), negate)
                } else {
                    // NAN-4283: `has(col, '<lowered>')` (raw compare) is only
                    // correct where the elements are lowercase at rest: the
                    // ClickHouse-table tag columns, and any array the profile
                    // marks lowercased at ingest. Other OCSF lake arrays keep
                    // producer case (`privileges`, `observables.type`,
                    // `finding_info.attacks.technique.uid`, hash values: the
                    // lake does not lowercase them, which is why the worker's
                    // prevalence probe lowers `hash.value` and its entity
                    // pruning tries several spellings), so has() silently
                    // matched nothing. They compare case-insensitively per
                    // element, like a scalar string. File pruning is
                    // unaffected: it keys on the query's candidate hints, not
                    // on this SQL shape.
                    if (super::is_array_column(field) && !self.profile.is_string_array_field(field))
                        || self.profile.is_lowercased_at_ingest(field)
                    {
                        let lit = escape_string(&s.to_lowercase());
                        let has = format!("has({}, '{}')", col, lit);
                        return Ok(if negate { format!("NOT {}", has) } else { has });
                    }
                    return Ok(self.array_membership_sql(
                        &col, if negate { "!=" } else { "=" }, value,
                    ));
                }
            }
            // NAN-4283: a bare `observables.value=10.1.5.40`,
            // `enrichments.data.is_rare=true` or `...host_count=3` parses to an
            // Ip/Bool/Number value. Equality is the same "any element equals"
            // as the quoted form; it used to fall through to a 400.
            (Comparator::Eq | Comparator::Ne, Value::Ip(_) | Value::Bool(_) | Value::Number(_)) => {
                return Ok(self.array_membership_sql(
                    &col, if *op == Comparator::Ne { "!=" } else { "=" }, value,
                ));
            }
            (Comparator::Contains | Comparator::NotContains, Value::String(s)) => {
                let pattern = escape_like_pattern(&escape_string(&s.to_lowercase()));
                (
                    format!("lower(x) iLike '%{}%'", pattern),
                    *op == Comparator::NotContains,
                )
            }
            (Comparator::Like | Comparator::NotLike, Value::String(s)) => {
                let pattern = wildcard_to_like_pattern(&s.to_lowercase());
                (
                    format!("lower(x) iLike '{}'", pattern),
                    *op == Comparator::NotLike,
                )
            }
            (Comparator::StartsWith | Comparator::NotStartsWith, Value::String(s)) => (
                format!(
                    "startsWith(lower(x), '{}')",
                    escape_string(&s.to_lowercase())
                ),
                *op == Comparator::NotStartsWith,
            ),
            (Comparator::EndsWith | Comparator::NotEndsWith, Value::String(s)) => (
                format!("endsWith(lower(x), '{}')", escape_string(&s.to_lowercase())),
                *op == Comparator::NotEndsWith,
            ),
            (Comparator::Regex | Comparator::NotRegex, Value::Regex(p)) => (
                format!("match(x, '{}')", escape_regex_pattern(p)),
                *op == Comparator::NotRegex,
            ),
            _ => {
                return Err(SqlGenError::InvalidQuery(format!(
                    "operator {:?} is not supported on array field '{}'",
                    op, field
                )))
            }
        };

        let exists = format!("arrayExists(x -> {}, {})", elem, col);
        Ok(if negate {
            format!("NOT {}", exists)
        } else {
            exists
        })
    }

    /// Generate SQL for UDM field filter (direct column or ext JSON access)
    ///
    /// In the hybrid schema:
    /// - Explicit columns are accessed directly (e.g., `src_ip = '1.2.3.4'`)
    /// - Other UDM fields are accessed via the ext JSON column (e.g., `ext.ssl_hash = 'abc'`)
    fn generate_udm_field_filter(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
    ) -> Result<String, SqlGenError> {
        if matches!(op, Comparator::Eq | Comparator::Ne) {
            if let (Value::String(label), Some(crate::schema::EnumIntMapping::Values(labels))) =
                (value, self.profile.enum_int_mapping(field)) {
                if !label.contains('*') && !label.contains('?') {
                    return Ok(format!("{} {} {}", self.filter_field_expr(field, "String"), comparator_to_sql(op), enum_values_literal_sql(field, labels, label)?));
                }
            }
        }
        // NAN-1464: Array(String) columns (`tags`, `*_tags`) use membership
        // semantics — a scalar `col = 'v'` is a ClickHouse type error that
        // silently matches nothing.
        if super::is_array_column(field) || self.profile.is_string_array_field(field) {
            return self.generate_array_field_filter(field, op, value);
        }

        // Profile-aware physical access: ExplicitColumn → escaped column (direct,
        // possibly dotted/promoted), JsonPath → native `event` subcolumn access
        // (OCSF tail, NAN-1426), Unknown →
        // `ext.{field}` (UDM's existing ext-JSON dot-notation, byte-identical).
        // NAN-1321: a class-split concept resolves to the value-pick `if(...)`.
        let field_expr = self.filter_field_expr(field, "String");

        // NAN-4286 (F30): the search-term form takes the same time literals
        // as `| where` (`time>"2026-10-20T22:30:00Z"` was chDB Code 53).
        if let Some(literal) = self.time_literal_sql(field, field, op, value)? {
            return Ok(format!("{} {} {}", field_expr, comparator_to_sql(op), literal));
        }

        // Check if the value contains wildcards (* or ?) and we're using Eq/Ne
        if let Value::String(s) = value {
            if (s.contains('*') || s.contains('?')) && matches!(op, Comparator::Eq | Comparator::Ne)
            {
                // NAN-2361: `field=*` is an EXISTENCE test, not "match all".
                // It used to compile to the literal `1`/`0`, which ignored the
                // field entirely and silently returned rows where it is absent.
                // A scalar exists when it is non-NULL and non-empty.
                if s == "*" {
                    let presence = self.scalar_presence_sql(field, &field_expr);
                    return Ok(if *op == Comparator::Eq {
                        presence
                    } else {
                        format!("NOT {presence}")
                    });
                }
                let pattern = wildcard_to_like_pattern(&s.to_lowercase());
                let sql_op = if *op == Comparator::Eq {
                    "iLike"
                } else {
                    "NOT iLike"
                };
                // NAN-1381: lowered, index-matchable form — bare `col iLike` cannot
                // use the `lower(col)` text indexes (CH matches a skip index by
                // EXPRESSION), and `lower()` never changes what iLike (already
                // case-insensitive) matches. Mirrors the Contains arm below.
                return Ok(format!(
                    "{} {} '{}'",
                    self.search_lowered(field, &field_expr),
                    sql_op,
                    pattern
                ));
            }
        }

        let value_sql = match value {
            Value::Regex(pattern) => format!("'{}'", escape_regex_pattern(pattern)),
            _ => value_to_sql_for_field(field, value, self.profile.as_ref()),
        };

        match op {
            Comparator::Regex => {
                // NAN-1026 Phase 2: simple regex literals lower to iLike (substring-
                // correct + splitByNonAlpha index-accelerated) instead of hasToken*.
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        let escaped = escape_string(&token);
                        let like = escape_like_pattern(&escaped);
                        let lhs = self.search_lowered(field, &field_expr);
                        let full = format!("{} iLike '%{}%'", lhs, like);
                        // NAN-1416: a multi-token literal (`/failed login/`,
                        // `/10.0.0.52/`) can't be served by the text index —
                        // AND a longest-token guard after it (full-needle
                        // first; see the Keyword arm for the ordering
                        // rationale). Only when the lhs is the bare
                        // `lower(col)` index expression; ext/JSON targets have
                        // no index to serve the guard.
                        if self.is_plain_string_search_column(field) {
                            if let Some(guard) = longest_guard_token(&token) {
                                return Ok(format!("{} AND {} iLike '%{}%'", full, lhs, guard));
                            }
                        }
                        return Ok(full);
                    }
                    // Complex regex — try bloom-guard pre-filtering and pattern rewrites
                    return Ok(build_optimized_regex_sql(
                        &field_expr,
                        pattern,
                        self.is_plain_string_search_column(field),
                        false,
                    ));
                }
                Ok(format!("match({}, {})", field_expr, value_sql))
            }
            Comparator::NotRegex => {
                // NAN-1026 Phase 2: NOT iLike instead of NOT hasToken — substring-correct.
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        let escaped = escape_string(&token.to_lowercase());
                        let like = escape_like_pattern(&escaped);
                        return Ok(format!(
                            "{} NOT iLike '%{}%'",
                            self.search_lowered(field, &field_expr),
                            like
                        ));
                    }
                    // Complex regex — try pattern rewrites (bloom guard not useful for negation)
                    return Ok(build_optimized_regex_sql(
                        &field_expr,
                        pattern,
                        self.is_plain_string_search_column(field),
                        true,
                    ));
                }
                // Use match() = 0 instead of NOT match() — ClickHouse optimizer
                // mishandles NOT match() when PREWHERE contains OR conditions.
                Ok(format!("match({}, {}) = 0", field_expr, value_sql))
            }
            Comparator::Like => {
                // Use iLike for case-insensitive matching. NAN-1381: lowered form so
                // the `lower(col)` text indexes apply — semantics unchanged, iLike is
                // already case-insensitive.
                Ok(format!(
                    "{} iLike {}",
                    self.search_lowered(field, &field_expr),
                    value_sql
                ))
            }
            Comparator::NotLike => Ok(format!(
                "{} NOT iLike {}",
                self.search_lowered(field, &field_expr),
                value_sql
            )),
            Comparator::Contains => {
                // NAN-1026 Phase 2: every CONTAINS lowers to substring iLike
                // (case-insensitive, substring-correct). splitByNonAlpha indexes
                // + CH 26.4 LIKE-via-dictionary-scan provide granule pruning so
                // perf is comparable to the old hasToken* path on indexed columns,
                // and the behavior is correct for fragment matches that hasToken
                // silently dropped (`message CONTAINS "anom"` matches "anomalous";
                // `src_host CONTAINS "dc"` matches "srv-dc01"; etc.).
                if let Value::String(s) = value {
                    let lowered = s.to_lowercase();
                    let escaped = escape_like_pattern(&escape_string(&lowered));
                    let lhs = self.search_lowered(field, &field_expr);
                    let full = format!("{} iLike '%{}%'", lhs, escaped);
                    // NAN-1416: multi-token needles bypass the text index —
                    // AND a longest-token guard after the full-needle iLike
                    // (full ∧ guard ≡ full; see the Keyword arm for the
                    // ordering rationale). Only when the lhs is the bare
                    // `lower(col)` index expression; ext/JSON targets have no
                    // index to serve the guard. Negated CONTAINS gets no guard
                    // (NOT full ≢ NOT full ∧ guard).
                    if self.is_plain_string_search_column(field) {
                        if let Some(token) = longest_guard_token(&lowered) {
                            return Ok(format!("{} AND {} iLike '%{}%'", full, lhs, token));
                        }
                    }
                    Ok(full)
                } else {
                    Ok(format!(
                        "{} iLike concat('%', {}, '%')",
                        field_expr, value_sql
                    ))
                }
            }
            Comparator::NotContains => {
                // NAN-1026 Phase 2: negated CONTAINS → NOT iLike, never NOT hasToken*.
                // The hasToken path used to leak DCs through `src_host NOT CONTAINS "dc"`
                // filters when host tokens were `dc01`, not `dc`.
                if let Value::String(s) = value {
                    let escaped = escape_like_pattern(&escape_string(&s.to_lowercase()));
                    Ok(format!(
                        "{} NOT iLike '%{}%'",
                        self.search_lowered(field, &field_expr),
                        escaped
                    ))
                } else {
                    Ok(format!(
                        "{} NOT iLike concat('%', {}, '%')",
                        field_expr, value_sql
                    ))
                }
            }
            Comparator::StartsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!(
                            "'{}%'",
                            escape_like_pattern(&escape_string(&s.to_lowercase()))
                        )
                    }
                    _ => format!("concat(lower({}), '%')", value_sql),
                };
                // NAN-1381: lowered, index-matchable form (see Like/Contains arms).
                Ok(format!(
                    "{} iLike {}",
                    self.search_lowered(field, &field_expr),
                    pattern
                ))
            }
            Comparator::NotStartsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!(
                            "'{}%'",
                            escape_like_pattern(&escape_string(&s.to_lowercase()))
                        )
                    }
                    _ => format!("concat(lower({}), '%')", value_sql),
                };
                // NAN-1381: lowered, index-matchable form (see Like/Contains arms).
                Ok(format!(
                    "{} NOT iLike {}",
                    self.search_lowered(field, &field_expr),
                    pattern
                ))
            }
            Comparator::EndsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!(
                            "'%{}'",
                            escape_like_pattern(&escape_string(&s.to_lowercase()))
                        )
                    }
                    _ => format!("concat('%', lower({}))", value_sql),
                };
                // NAN-1381: lowered, index-matchable form (see Like/Contains arms).
                Ok(format!(
                    "{} iLike {}",
                    self.search_lowered(field, &field_expr),
                    pattern
                ))
            }
            Comparator::NotEndsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!(
                            "'%{}'",
                            escape_like_pattern(&escape_string(&s.to_lowercase()))
                        )
                    }
                    _ => format!("concat('%', lower({}))", value_sql),
                };
                // NAN-1381: lowered, index-matchable form (see Like/Contains arms).
                Ok(format!(
                    "{} NOT iLike {}",
                    self.search_lowered(field, &field_expr),
                    pattern
                ))
            }
            Comparator::Eq | Comparator::Ne => {
                let sql_op = comparator_to_sql(op);

                // For numeric UDM fields, never apply lower() - compare as numbers
                // (NAN-1534: also the active dataset's numeric columns, e.g. duration_ns).
                if self.field_is_numeric(field) {
                    match value {
                        Value::String(s) => {
                            // Convert string to number for comparison (handles drilldown from UI)
                            // Use toInt64OrZero for safe conversion of potentially non-numeric strings
                            if s.parse::<i64>().is_ok() {
                                Ok(format!("{} {} {}", field_expr, sql_op, s))
                            } else if s.parse::<f64>().is_ok() {
                                Ok(format!("{} {} {}", field_expr, sql_op, s))
                            } else if let Some(mapping) = self.profile.enum_int_mapping(field) {
                                // NAN-1382 (G6): a verb on a NATIVE enum-int column
                                // (`status_id="failure"`, `severity_id="high"`) translates
                                // via the manifest enum metadata instead of the dead
                                // `toString(<int>) = 'verb'` fallback (which matches 0
                                // rows). Fixed table → indexed int compare (loud error on
                                // an unknown label); class-scoped (activity_id) → sibling
                                // label String column. UDM has no enum-int columns → None
                                // → byte-identical.
                                match mapping {
                                    crate::schema::EnumIntMapping::Values(labels) => Ok(format!(
                                        "{} {} {}",
                                        field_expr,
                                        sql_op,
                                        enum_values_literal_sql(field, labels, s)?
                                    )),
                                    crate::schema::EnumIntMapping::LabelColumn(sibling) => {
                                        Ok(format!(
                                            "lower({}) {} '{}'",
                                            escape_identifier(sibling),
                                            sql_op,
                                            escape_string(&s.to_lowercase())
                                        ))
                                    }
                                }
                            } else {
                                if self.profile.id() == crate::schema::SchemaId::Ocsf {
                                    return Err(SqlGenError::InvalidQuery(format!("Cannot resolve label '{s}' for numeric OCSF field '{field}'; use an integer id")));
                                }
                                // Non-numeric string on numeric field - use toString for comparison
                                Ok(format!(
                                    "toString({}) {} '{}'",
                                    field_expr,
                                    sql_op,
                                    escape_string(s)
                                ))
                            }
                        }
                        _ => Ok(format!("{} {} {}", field_expr, sql_op, value_sql)),
                    }
                } else if self.field_is_boolean(field) {
                    Ok(self.boolean_comparison_sql(&field_expr, sql_op, value))
                } else if self.profile.is_uuid_field(field) {
                    // UUID fields: compare via toString() — lower() doesn't work on UUID type
                    match value {
                        Value::String(s) => Ok(format!(
                            "toString({}) {} '{}'",
                            field_expr,
                            sql_op,
                            escape_string(&s.to_lowercase())
                        )),
                        _ => Ok(format!("{} {} {}", field_expr, sql_op, value_sql)),
                    }
                } else {
                    // Case-insensitive string comparison for text fields
                    match value {
                        Value::String(s) => {
                            let escaped_lower = escape_string(&s.to_lowercase());

                            // Hostname expansion: for host-entity fields without dots,
                            // match both exact and FQDN variants (e.g., "workstation"
                            // matches "workstation.corp.local"). Driven by the active
                            // profile's entity classification so OCSF promoted host
                            // columns (e.g. `src_endpoint.hostname`) expand too — for
                            // UDM these are exactly the host-entity columns.
                            // Single source of truth, shared with the lake
                            // compiler's candidate-hint gate (see the helper).
                            let expands =
                                hostname_equality_expands(self.profile.as_ref(), field, s);
                            let is_hostname_field = self.profile.entity_type(field)
                                == Some(crate::schema::EntityType::Host);
                            let has_no_dot = !s.contains('.');

                            if expands && *op == Comparator::Eq {
                                // Expand: exact match OR starts with "value."
                                // NAN-3154: on the object lake an ingest-lowercased
                                // column compares RAW in both legs (the form the
                                // plain Eq arm below emits), so the equality leg
                                // keeps its Parquet bloom / row-group pruning.
                                let lhs = self.host_prefix_lhs(field, &field_expr);
                                Ok(format!(
                                    "({} = '{}' OR startsWith({}, '{}.'))",
                                    lhs, escaped_lower, lhs, escaped_lower
                                ))
                            } else if is_hostname_field && has_no_dot && *op == Comparator::Ne {
                                // Negated: NOT exact AND NOT starts with "value."
                                Ok(format!(
                                    "(lower({}) != '{}' AND NOT startsWith(lower({}), '{}.'))",
                                    field_expr, escaped_lower, field_expr, escaped_lower
                                ))
                            } else if *op == Comparator::Eq
                                && self.is_resolved_lowercased_at_ingest(field)
                            {
                                // For fields normalized to lowercase at ingest, skip lower() wrapper
                                // This allows efficient index usage (set indexes, bloom filters).
                                // Judged on the profile-RESOLVED column so OCSF UDM-aliases
                                // (src_ip → src_endpoint.ip) keep their bloom pruning now that
                                // the raw-form PREWHERE duplicate is gone (NAN-1412).
                                // Eq ONLY: for Eq the raw form is row-identical to the
                                // lower() form while the ingest-lowercase invariant holds;
                                // for Ne it is not (an uppercase row flips from excluded to
                                // included), and a bloom can never prune a negation anyway —
                                // Ne falls through to the lower() form (NAN-1643).
                                Ok(format!("{} {} '{}'", field_expr, sql_op, escaped_lower))
                            } else {
                                Ok(format!(
                                    "lower({}) {} '{}'",
                                    field_expr, sql_op, escaped_lower
                                ))
                            }
                        }
                        _ => Ok(format!("{} {} {}", field_expr, sql_op, value_sql)),
                    }
                }
            }
            _ => {
                // Numeric comparisons (Gt, Lt, Gte, Lte) - no case handling needed
                let sql_op = comparator_to_sql(op);
                // NAN-4276: `value_to_sql_for_field` quotes a number for a
                // String column, which made `metadata.event_code>4000` a
                // lexicographic compare ('500' > '4000'). Compare the column's
                // numeric value instead; non-numeric text gives NULL (excluded).
                if matches!(value, Value::Number(_))
                    && !self.field_is_numeric(field)
                    && is_text_column(field, self.profile.as_ref())
                {
                    return Ok(format!(
                        "toFloat64OrNull(toString({})) {} {}",
                        field_expr,
                        sql_op,
                        value_to_sql(value)
                    ));
                }
                Ok(format!("{} {} {}", field_expr, sql_op, value_sql))
            }
        }
    }

    /// Generate SQL for extended/metadata field filter
    ///
    /// By default, searches the `ext` JSON column where parser-defined queryable fields live.
    /// Use `metadata_field` or `metadata.field` prefix to search the metadata column instead.
    fn generate_json_field_filter(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
    ) -> Result<String, SqlGenError> {
        // Check for explicit metadata column targeting via prefix
        let (use_metadata, field_path) = if let Some(stripped) = field.strip_prefix("metadata_") {
            (true, stripped.to_string())
        } else if let Some(stripped) = field.strip_prefix("metadata.") {
            (true, stripped.to_string())
        } else {
            (false, field.to_string())
        };

        // Generate field expression: ext.field or JSONExtract for metadata.
        // NAN-1383: the suffix interpolates into `JSONExtract{suffix}` and the
        // typed extractor for Float64 is `JSONExtractFloat` (there is NO
        // `JSONExtractFloat64` in ClickHouse — emitting it 400s with
        // UNKNOWN_FUNCTION on every numeric comparison routed through JSON
        // extraction: metadata.* under both profiles, unmapped `event` tail
        // fields under OCSF).
        let json_type = match value {
            Value::Number(_) => "Float",
            Value::Bool(_) => "Bool",
            _ => "String",
        };
        let field_expr = if use_metadata {
            // Use JSONExtract for metadata column access
            self.generate_json_extract(&field_path, json_type)
        } else {
            // Profile-aware spill access. For UDM the profile returns Unknown →
            // `ext.{field}` (byte-identical to the prior native-dot-notation). For
            // OCSF an unpromoted tail field resolves to JsonPath → native `event`
            // subcolumn access (NAN-1426). NAN-1321: OCSF UDM-semantic
            // aliases (`src_host`, `user`, …) are not promoted columns so they reach
            // THIS path; `filter_field_expr` resolves the class-split ones to the
            // value-pick `if(...)` so `src_host="ws-01"` matches device.hostname too.
            self.filter_field_expr(&field_path, json_type)
        };

        // String/pattern comparisons compare against toString(field) so a missing ext key
        // (JSON null) becomes '' rather than NULL. Otherwise a negated match (`NOT iLike`,
        // `!=`, or an outer `NOT (... iLike ...)`) evaluates `NOT NULL` = NULL and silently
        // drops every row where the key is absent — e.g. `NOT integrity_level CONTAINS "x"`
        // returned only the rows that HAVE the field. The post-pipe `| where` path already
        // does this. Numeric comparisons keep the raw field (toString would break them), and
        // build_optimized_regex_sql is passed the raw field_expr (it wraps internally). NAN-1161.
        let field_str = format!("toString({})", field_expr);

        // NAN-1381: when the field resolves to a plain non-null String column
        // (class-split unified, or a promoted String column reached via a UDM
        // alias) the toString guard is a pure pessimization: ClickHouse matches
        // a skip index by EXPRESSION, so `toString(col)` orphans every
        // `lower(col)` text/bloom index (600/600 granules read vs 55/600 via
        // idx_user_unified_words on a `user CONTAINS` probe, local CH) while
        // being a semantic no-op on a non-Nullable String column — the NAN-1161
        // missing-key concern cannot apply, the column always exists. The
        // case-insensitive pattern arms (iLike / wildcard / simple-regex /
        // prefix / suffix) therefore use `lower(col)` — the exact index
        // expression — for these targets. Case-SENSITIVE arms (full `match()`)
        // and ext/JSON/metadata targets keep `field_str` untouched.
        let plain_string_target =
            !use_metadata && self.resolves_to_plain_string_column(&field_path);
        let pattern_expr = if plain_string_target {
            format!("lower({})", field_expr)
        } else {
            field_str.clone()
        };

        // Check if the value contains wildcards (* or ?) and we're using Eq/Ne
        if let Value::String(s) = value {
            if (s.contains('*') || s.contains('?')) && matches!(op, Comparator::Eq | Comparator::Ne)
            {
                // NAN-2361: `field=*` is an EXISTENCE test, not "match all".
                // It used to compile to the literal `1`/`0`, which ignored the
                // field entirely and silently returned rows where it is absent.
                // A scalar exists when it is non-NULL and non-empty.
                if s == "*" {
                    let presence = if use_metadata {
                        format!("({field_expr} IS NOT NULL AND {field_expr} != '')")
                    } else {
                        self.scalar_presence_sql(&field_path, &field_expr)
                    };
                    return Ok(if *op == Comparator::Eq {
                        presence
                    } else {
                        format!("NOT {presence}")
                    });
                }
                let pattern = wildcard_to_like_pattern(&s.to_lowercase());
                let sql_op = if *op == Comparator::Eq {
                    "iLike"
                } else {
                    "NOT iLike"
                };
                return Ok(format!("{} {} '{}'", pattern_expr, sql_op, pattern));
            }
        }

        // NAN-1161: string/pattern arms compare `pattern_expr` (= toString(field_expr), or
        // lower(col) for plain String columns — see the bindings above) so a missing ext key
        // reads as '' not NULL. build_optimized_regex_sql gets the raw field_expr (it wraps
        // internally); the numeric arm stays raw.
        match op {
            Comparator::Regex => {
                // For simple patterns (no regex metacharacters), use substring iLike.
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        // NAN-1160: substring iLike, not hasTokenCaseInsensitive. hasToken
                        // matches whole tokens only (`dc` never matches `dc01`) and ext is
                        // native JSON with no token index (idx_ext_text dropped, migration 118),
                        // so hasToken under-matched AND bought no acceleration.
                        return Ok(format!(
                            "{} iLike '%{}%'",
                            pattern_expr,
                            escape_like_pattern(&escape_string(&token.to_lowercase()))
                        ));
                    }
                    // Complex regex — try bloom filter pre-filtering and pattern rewrites
                    return Ok(build_optimized_regex_sql(
                        &field_expr,
                        pattern,
                        plain_string_target,
                        false,
                    ));
                }
                Ok(format!("match({}, {})", field_str, value_to_sql(value)))
            }
            Comparator::NotRegex => {
                // For simple patterns, use substring NOT iLike (see Regex above, NAN-1160).
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        return Ok(format!(
                            "{} NOT iLike '%{}%'",
                            pattern_expr,
                            escape_like_pattern(&escape_string(&token.to_lowercase()))
                        ));
                    }
                    // Complex regex — try pattern rewrites
                    return Ok(build_optimized_regex_sql(
                        &field_expr,
                        pattern,
                        plain_string_target,
                        true,
                    ));
                }
                Ok(format!("match({}, {}) = 0", field_str, value_to_sql(value)))
            }
            Comparator::Like => Ok(format!("{} iLike {}", pattern_expr, value_to_sql(value))),
            Comparator::NotLike => Ok(format!(
                "{} NOT iLike {}",
                pattern_expr,
                value_to_sql(value)
            )),
            Comparator::Contains => {
                if let Value::String(s) = value {
                    // NAN-1160: always substring iLike, never hasTokenCaseInsensitive. hasToken
                    // matched whole tokens only (`medi` never matches `Medium`) and ext is native
                    // JSON with no token index (idx_ext_text dropped, migration 118) — wrong AND
                    // no faster. Mirrors the UDM Contains path.
                    let escaped = escape_like_pattern(&escape_string(&s.to_lowercase()));
                    Ok(format!("{} iLike '%{}%'", pattern_expr, escaped))
                } else {
                    Ok(format!(
                        "{} iLike concat('%', {}, '%')",
                        pattern_expr,
                        value_to_sql(value)
                    ))
                }
            }
            Comparator::NotContains => {
                if let Value::String(s) = value {
                    // NAN-1160: NOT iLike, never NOT hasTokenCaseInsensitive — the token form
                    // leaked sub-token matches through the exclusion (e.g. `NOT CONTAINS "medi"`
                    // failed to exclude `Medium`).
                    let escaped = escape_like_pattern(&escape_string(&s.to_lowercase()));
                    Ok(format!("{} NOT iLike '%{}%'", pattern_expr, escaped))
                } else {
                    Ok(format!(
                        "{} NOT iLike concat('%', {}, '%')",
                        pattern_expr,
                        value_to_sql(value)
                    ))
                }
            }
            Comparator::StartsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!(
                            "'{}%'",
                            escape_like_pattern(&escape_string(&s.to_lowercase()))
                        )
                    }
                    _ => format!("concat(lower({}), '%')", value_to_sql(value)),
                };
                Ok(format!("{} iLike {}", pattern_expr, pattern))
            }
            Comparator::NotStartsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!(
                            "'{}%'",
                            escape_like_pattern(&escape_string(&s.to_lowercase()))
                        )
                    }
                    _ => format!("concat(lower({}), '%')", value_to_sql(value)),
                };
                Ok(format!("{} NOT iLike {}", pattern_expr, pattern))
            }
            Comparator::EndsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!(
                            "'%{}'",
                            escape_like_pattern(&escape_string(&s.to_lowercase()))
                        )
                    }
                    _ => format!("concat('%', lower({}))", value_to_sql(value)),
                };
                Ok(format!("{} iLike {}", pattern_expr, pattern))
            }
            Comparator::NotEndsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!(
                            "'%{}'",
                            escape_like_pattern(&escape_string(&s.to_lowercase()))
                        )
                    }
                    _ => format!("concat('%', lower({}))", value_to_sql(value)),
                };
                Ok(format!("{} NOT iLike {}", pattern_expr, pattern))
            }
            Comparator::Eq | Comparator::Ne => {
                // Case-insensitive string comparison. NAN-1161: lower(toString(field)) so a
                // missing key compares as '' — `field != "x"` keeps absent-key rows (NULL != x
                // would drop them).
                let sql_op = comparator_to_sql(op);
                // NAN-1382 (G6): a UDM verb-valued alias whose resolved OCSF column is
                // an enum-encoded INT (`auth_result` → `status_id` UInt32) cannot be
                // string-compared — `lower(toString(status_id)) = 'failure'` matches 0
                // rows against 127k `status_id = 2` rows. Translate the verb via the
                // manifest enum metadata: a fixed label table compares the indexed int
                // (`status_id = 2`); a class-scoped enum (activity_id, whose int
                // meaning depends on class_uid) compares the sibling label String
                // column instead (`lower(activity) = 'logon'`). Numeric strings pass
                // through as the id; an unknown label on a fixed table fails LOUDLY.
                // UDM returns no mapping (verbs are String columns) → byte-identical.
                if !use_metadata {
                    if let (Value::String(s), Some(mapping)) =
                        (value, self.profile.enum_int_mapping(&field_path))
                    {
                        return match mapping {
                            crate::schema::EnumIntMapping::Values(labels) => Ok(format!(
                                "{} {} {}",
                                field_expr,
                                sql_op,
                                enum_values_literal_sql(&field_path, labels, s)?
                            )),
                            crate::schema::EnumIntMapping::LabelColumn(sibling) => {
                                if let Ok(id) = s.parse::<i64>() {
                                    // The integer id targets the int column directly
                                    // (parsed, so "+2"/"007" emit canonically).
                                    Ok(format!("{} {} {}", field_expr, sql_op, id))
                                } else {
                                    Ok(format!(
                                        "lower({}) {} '{}'",
                                        escape_identifier(sibling),
                                        sql_op,
                                        escape_string(&s.to_lowercase())
                                    ))
                                }
                            }
                        };
                    }
                }
                if self.field_is_boolean(&field_path) {
                    return Ok(self.boolean_comparison_sql(&field_expr, sql_op, value));
                }
                // NAN-2361: array leaves need membership, not scalar comparison.
                // Checked AFTER boolean/enum so a scalar column keeps its exact
                // existing form; only genuinely Array-typed fields divert here.
                if self.field_is_array(&field_path) {
                    return Ok(self.array_membership_sql(&field_expr, sql_op, value));
                }
                match value {
                    // NAN-1333: a class-split concept resolves to its INDEXED unified
                    // column (`<field>_unified`), a plain non-null String/LowCardinality
                    // column. The `toString` wrapper that NAN-1161 adds for ext/JSON-null
                    // safety ORPHANS the `lower(<col>)` text index here (CH matches a skip
                    // index by EXPRESSION) → full scan. Drop it for class-split fields so
                    // `lower(<col>_unified) = v` matches the words index and prunes
                    // (640/640 → 294/640 on local CH). toString on a real String column is
                    // a semantic no-op, and the column is NOT NULL (MATERIALIZED ''), so the
                    // NAN-1161 absent-key concern does not apply. UDM never class-splits →
                    // this branch is OCSF-only → UDM byte-identical.
                    // NAN-1381 broadened the guard from class-split-only to every plain
                    // non-null String target (a UDM alias resolving to a promoted String
                    // column gets the same index-preserving form).
                    // NAN-1412: when the resolved column is lowercase-normalized at
                    // ingest (src_endpoint.ip & co.), drop the lower() wrapper entirely —
                    // those columns carry RAW-expression bloom indexes, which
                    // `lower(col) =` orphans. Pre-NAN-1412 the explicit-PREWHERE
                    // duplicate carried the raw form (resolved inside
                    // `extract_prewhere_conditions`) and rescued the pruning; with the
                    // single WHERE this is the only emission (EXPLAIN-verified:
                    // idx_src_endpoint_ip 553→88 granules). Class-split concepts are
                    // excluded by the helper and keep the lower() form their
                    // `lower(<col>_unified)` text index serves.
                    // Eq ONLY: for Eq the raw form is row-identical to the old
                    // PREWHERE(raw) ∧ WHERE(lower) conjunction even against
                    // invariant-violating data; for Ne it is not (an uppercase row
                    // flips from excluded to included), and a bloom can never prune
                    // a negation anyway — keep Ne on the lower() form.
                    Value::String(s)
                        if plain_string_target
                            && *op == Comparator::Eq
                            && self.is_resolved_lowercased_at_ingest(&field_path) =>
                    {
                        Ok(format!(
                            "{} {} '{}'",
                            field_expr,
                            sql_op,
                            escape_string(&s.to_lowercase())
                        ))
                    }
                    Value::String(s) if plain_string_target => Ok(format!(
                        "lower({}) {} '{}'",
                        field_expr,
                        sql_op,
                        escape_string(&s.to_lowercase())
                    )),
                    Value::String(s) => Ok(format!(
                        "lower({}) {} '{}'",
                        field_str,
                        sql_op,
                        escape_string(&s.to_lowercase())
                    )),
                    _ => Ok(format!("{} {} {}", field_expr, sql_op, value_to_sql(value))),
                }
            }
            _ => {
                // Numeric comparisons
                let sql_op = comparator_to_sql(op);
                // O44 (NAN-1721): a span/metrics attribute Map value is a String
                // (`attributes['x']`), so a numeric range against it (`x > 5`) is
                // otherwise String-vs-number → CH "no common type". Coerce the Map
                // access to Float64 (and a non-numeric literal likewise → NULL, so
                // the row is excluded) so the comparison is numeric. MapKey targets
                // are spans/metrics-only; UDM `ext`/`metadata` and OCSF `event`
                // numeric compares already emit a typed `JSONExtract*`/subcolumn
                // extractor, so those stay byte-identical.
                if self.resolves_to_map_key(&field_path) {
                    let rhs = match value {
                        Value::String(s) if s.parse::<f64>().is_err() => {
                            format!("toFloat64OrNull({})", value_to_sql(value))
                        }
                        Value::String(s) => s.clone(),
                        _ => value_to_sql(value),
                    };
                    return Ok(format!(
                        "toFloat64OrNull({}) {} {}",
                        field_expr, sql_op, rhs
                    ));
                }
                Ok(format!("{} {} {}", field_expr, sql_op, value_to_sql(value)))
            }
        }
    }

    /// Generate ClickHouse JSONExtract expression for metadata field access
    ///
    /// Handles:
    /// - Simple fields: metadata_field -> JSONExtractString(metadata, 'field')
    /// - Nested fields: a.b.c -> JSONExtractString(metadata, 'a', 'b', 'c')
    /// - Type-specific extraction: JSONExtractString, JSONExtractInt, JSONExtractFloat, JSONExtractBool
    ///
    /// OCSF Phase 2: when the active profile resolves `field` to a
    /// [`FieldResolution::JsonPath`] (a nested path in an arbitrary JSON column,
    /// e.g. OCSF's `event` column), emit native subcolumn access against that
    /// column via [`json_tail_access_sql`] (NAN-1426 — the previous N-level
    /// `JSONExtract<T>(col, 'p1', …)` re-serialized the entire `event` object
    /// per row; parity carve-outs documented on the helper). For UDM the
    /// profile only ever returns `ExplicitColumn` or `Unknown` — neither hits the
    /// JsonPath branch — so the legacy `metadata`-prefixed behavior below is
    /// preserved byte-for-byte.
    pub fn generate_json_extract(&self, field: &str, json_type: &str) -> String {
        // OCSF nested-path resolution (additive; never exercised by UDM).
        if let crate::schema::FieldResolution::JsonPath { col, path } = self.profile.resolve(field)
        {
            return json_tail_access_sql(&col, &path, json_type);
        }

        // Handle metadata_ prefix: metadata_endpoint -> JSONExtract(metadata, 'endpoint')
        let field_path = if let Some(stripped) = field.strip_prefix("metadata_") {
            stripped.to_string()
        } else {
            field.to_string()
        };

        // Handle dot notation for nested paths
        let parts: Vec<&str> = field_path.split('.').collect();
        let path_args: Vec<String> = parts
            .iter()
            .map(|p| format!("'{}'", escape_string(p)))
            .collect();

        format!(
            "JSONExtract{}(metadata, {})",
            json_type,
            path_args.join(", ")
        )
    }

    /// Generate ClickHouse time bucket expression
    ///
    /// Maps span durations to ClickHouse time functions:
    /// - < 60s: toStartOfSecond or toStartOfInterval
    /// - 60s: toStartOfMinute
    /// - 300s (5m): toStartOfFiveMinutes
    /// - 600s (10m): toStartOfTenMinutes
    /// - 900s (15m): toStartOfFifteenMinutes
    /// - 3600s (1h): toStartOfHour
    /// - 86400s (1d): toStartOfDay
    /// - 604800s (1w): toStartOfWeek
    /// - 2592000s (30d): toStartOfMonth
    pub fn generate_time_bucket(&self, span: &std::time::Duration) -> String {
        let secs = span.as_secs();
        // NAN-1555: bucket on the active dataset's time column (`start_time` for
        // spans). Logs/metrics keep `timestamp` → byte-identical.
        let tc = self.time_column();

        match secs {
            s if s < 60 => {
                // Use toStartOfInterval for sub-minute intervals
                format!("toStartOfInterval({tc}, INTERVAL {} SECOND)", s)
            }
            60 => format!("toStartOfMinute({tc})"),
            300 => format!("toStartOfFiveMinutes({tc})"),
            600 => format!("toStartOfTenMinutes({tc})"),
            900 => format!("toStartOfFifteenMinutes({tc})"),
            3600 => format!("toStartOfHour({tc})"),
            86400 => format!("toStartOfDay({tc})"),
            604800 => format!("toStartOfWeek({tc})"),
            s if s >= 2592000 => format!("toStartOfMonth({tc})"),
            _ => {
                // For non-standard intervals, use toStartOfInterval
                if secs % 3600 == 0 {
                    format!("toStartOfInterval({tc}, INTERVAL {} HOUR)", secs / 3600)
                } else if secs % 60 == 0 {
                    format!("toStartOfInterval({tc}, INTERVAL {} MINUTE)", secs / 60)
                } else {
                    format!("toStartOfInterval({tc}, INTERVAL {} SECOND)", secs)
                }
            }
        }
    }

    /// Generate SQL for a WHERE condition in piped commands (after stats, etc.)
    /// This treats all fields as direct column references, not JSON metadata
    pub(super) fn generate_where_condition(
        &self,
        expr: &SearchExpr,
    ) -> Result<String, SqlGenError> {
        match expr {
            SearchExpr::Keyword(kw) => {
                if kw == "*" {
                    return Ok("1".to_string());
                }
                // In piped commands (search, where), bare keywords are message text
                // searches. Mirror the top-level Keyword arm exactly via the shared
                // helper: hasAllTokens drives the splitByNonAlpha text index by a
                // posting-list lookup (NAN-1515), replacing the prior substring iLike
                // (NAN-1153 had already moved this off position(), which full-scanned
                // the message column). The predicate pushes down through the stage CTEs
                // to the table read where idx_message_words serves it. After
                // stats/timechart where message no longer exists, ClickHouse returns a
                // clear "column not found" error — correct, since bare keyword searches
                // don't make sense after aggregation. NAN-1555: the indexed text
                // column is profile-driven (`span_name` for spans).
                // NAN-1828: OR-folded across every body column (OCSF adds
                // `raw_data`; single-column profiles are byte-identical).
                Ok(bare_keyword_predicate(
                    kw,
                    &self.profile.keyword_search_columns(),
                    self.keyword_term_adjacency,
                ))
            }
            SearchExpr::FieldFilter {
                field,
                op,
                value,
                rhs,
            } => {
                // NAN-2378/NAN-2380: `a = b` where `b` is a column, not a
                // literal. Same resolution as the base-scope arm; see
                // `field_to_field_term`.
                if let Some(term) = self.where_scope_computed_field_term(field, op, value, *rhs) {
                    return self.generate_where_condition(&term);
                }
                if let Some(term) = self.field_to_field_term(field, op, value, *rhs)? {
                    return self.generate_where_condition(&term);
                }
                let original_field = field.as_str();
                // Normalize field name (apply aliases like command_line -> process).
                // NAN-1555: profile-aware (spans keep `service_name`); logs identical.
                let field = self.canonicalize_field(field);
                // Check if field is an aggregation expression like "avg(bytes_out)"
                // If so, extract the function name to use as the column reference
                let column_ref = if field.contains('(') && field.contains(')') {
                    // Only allow known aggregation function names as column refs
                    if let Some(func_end) = field.find('(') {
                        let func_name = &field[..func_end];
                        match func_name.to_lowercase().as_str() {
                            "count" | "sum" | "avg" | "min" | "max" | "dc" | "values" | "first"
                            | "last" | "stdev" | "stdevp" | "var" | "varp" | "median" | "perc"
                            | "list" | "earliest" | "latest" | "rate" | "per_second"
                            | "per_minute" | "per_hour" => escape_identifier(func_name),
                            _ => {
                                return Err(SqlGenError::InvalidQuery(format!(
                                    "Invalid field name '{}': contains parentheses. Field names may only contain letters, digits, underscores, and dots.",
                                    field
                                )));
                            }
                        }
                    } else {
                        escape_identifier(field)
                    }
                } else {
                    // SECURITY: Validate field name format for regular fields
                    crate::query::validation::validate_field_name_format(field)
                        .map_err(|e| SqlGenError::InvalidQuery(e.message))?;
                    // {func}_{field} reference to an UN-aliased prior aggregation
                    // (NAN-1339): the output column is the bare func name.
                    if let Some(target) = self.agg_reference_alias(field) {
                        escape_identifier(&target)
                    } else if self.resolves_to_map_key(field) && !self.is_computed_field(field) {
                        // NAN-1555: a spans/metrics attribute tag in a `| where`
                        // re-derives the `attributes['key']` Map subscript (the
                        // `attributes`/`resource_attributes` columns pass through the
                        // `SELECT *` that `Command::Where` forces), instead of a bare
                        // column reference that does not exist → CH Code 47. UDM/OCSF
                        // never yield MapKey, so the logs `where` path is unchanged.
                        // NAN-1557: but a pipeline-computed name (a stats output like
                        // `count` in `… | stats count by x | where count > N`) is a
                        // real in-scope column of the upstream stage, NOT an
                        // attribute — `is_computed_field` excludes it so it stays a
                        // bare reference (the stats stage carries no `attributes`).
                        self.field_access_expr(field, "String")
                    } else if let Some(resolved) =
                        self.where_scope_schema_alias_expr(original_field, field)
                    {
                        resolved
                    } else {
                        escape_identifier(field)
                    }
                };

                // NAN-2361: `field=*` is an EXISTENCE test here too. The
                // pipeline path had the inverse of the search-term bug: rather
                // than collapsing to `1` (match all) it fell through to a plain
                // equality and emitted `lower("user") = '*'`, matching only rows
                // whose value is the literal asterisk — i.e. nothing. Both arms
                // now agree that `=*` means present and `!=*` means absent.
                if let Value::String(s) = value {
                    if s == "*" && matches!(op, Comparator::Eq | Comparator::Ne) {
                        // NAN-2707: a numeric prevalence column carries the
                        // N/A sentinel, which is "absent", not a value.
                        let presence = if self.is_prevalence_sentinel_field(field) {
                            format!(
                                "({column_ref} IS NOT NULL AND {column_ref} != {PREVALENCE_NA_SENTINEL})"
                            )
                        } else {
                            format!(
                                "(toString({column_ref}) IS NOT NULL AND toString({column_ref}) != '')"
                            )
                        };
                        return Ok(if *op == Comparator::Eq {
                            presence
                        } else {
                            format!("NOT {presence}")
                        });
                    }
                }

                // NAN-4285: `| where ip=10.0.0.0/8` on an IP field is network
                // membership, as the search term is (a string compare with the
                // CIDR text matched nothing). `!=` keeps the presence rule of
                // the search-term `!=`.
                if matches!(op, Comparator::Eq | Comparator::Ne) && list_has_cidr(std::slice::from_ref(value)) {
                    if let Some(sql) = self.cidr_in_list_predicate(field, &column_ref, std::slice::from_ref(value), *op == Comparator::Ne, |_| Ok("0".to_string()))? {
                        return Ok(sql);
                    }
                }

                // NAN-4286 (F30): a literal against the event-time column takes
                // the same forms the API accepts for `time_range`.
                if let Some(literal) = self.time_literal_sql(original_field, field, op, value)? {
                    return Ok(format!("{} {} {}", column_ref, comparator_to_sql(op), literal));
                }

                // NAN-4276: a numeric literal against a String column. Equality
                // compares it as the text it was written as (exactly the
                // search-term form `metadata.event_code=7`); a range compares
                // the column's numeric value, since a lexicographic `'500' >
                // '4000'` is never what `> 4000` means. Non-numeric values give
                // NULL and the row is excluded.
                if let Value::Number(_) = value {
                    if self.where_scope_text_operand(original_field, field) {
                        match op {
                            Comparator::Eq | Comparator::Ne => {
                                return self.generate_where_condition(&SearchExpr::FieldFilter {
                                    field: original_field.to_string(),
                                    op: op.clone(),
                                    value: Value::String(value_to_sql(value)),
                                    rhs: RhsSyntax::Literal,
                                });
                            }
                            Comparator::Gt | Comparator::Lt | Comparator::Gte | Comparator::Lte => {
                                return Ok(format!(
                                    "toFloat64OrNull(toString({})) {} {}",
                                    column_ref,
                                    comparator_to_sql(op),
                                    value_to_sql(value)
                                ));
                            }
                            _ => {}
                        }
                    }
                }

                // Always treat as direct column reference
                let value_sql = match value {
                    Value::Regex(pattern) => format!("'{}'", escape_regex_pattern(pattern)),
                    _ => value_to_sql(value),
                };

                match op {
                    Comparator::Regex => {
                        // For simple patterns, use substring iLike (NAN-1160).
                        if let Value::Regex(pattern) = value {
                            if let Some(token) = extract_simple_regex_token(pattern) {
                                // NAN-1160: substring iLike, not hasTokenCaseInsensitive —
                                // post-stats columns are unindexed CTE intermediates, so
                                // hasToken under-matched (`dc` ≠ `dc01`) for zero index gain.
                                return Ok(format!(
                                    "toString({}) iLike '%{}%'",
                                    column_ref,
                                    escape_like_pattern(&escape_string(&token.to_lowercase()))
                                ));
                            }
                            // Complex regex — try bloom filter pre-filtering and pattern rewrites.
                            // NAN-1640: skip_tostring=false deliberately withholds the
                            // anchored prefix/suffix text-index guard — where-pipe targets
                            // are toString-wrapped CTE intermediates with no `lower(col)`
                            // index to serve it (where-pipe form selection is finding 2.1).
                            let col_str = format!("toString({})", column_ref);
                            return Ok(build_optimized_regex_sql(&col_str, pattern, false, false));
                        }
                        Ok(format!("match(toString({}), {})", column_ref, value_sql))
                    }
                    Comparator::NotRegex => {
                        // For simple patterns, use substring NOT iLike (NAN-1160).
                        if let Value::Regex(pattern) = value {
                            if let Some(token) = extract_simple_regex_token(pattern) {
                                return Ok(format!(
                                    "toString({}) NOT iLike '%{}%'",
                                    column_ref,
                                    escape_like_pattern(&escape_string(&token.to_lowercase()))
                                ));
                            }
                            // Complex regex — try pattern rewrites
                            let col_str = format!("toString({})", column_ref);
                            return Ok(build_optimized_regex_sql(&col_str, pattern, false, true));
                        }
                        Ok(format!(
                            "match(toString({}), {}) = 0",
                            column_ref, value_sql
                        ))
                    }
                    Comparator::Like => Ok(format!("toString({}) iLike {}", column_ref, value_sql)),
                    Comparator::NotLike => {
                        Ok(format!("toString({}) NOT iLike {}", column_ref, value_sql))
                    }
                    Comparator::Contains => {
                        if let Value::String(s) = value {
                            // NAN-1160: always substring iLike, never hasTokenCaseInsensitive —
                            // post-stats columns are unindexed CTE intermediates, so hasToken
                            // matched whole tokens only (`medi` ≠ `Medium`) for zero index gain.
                            let escaped = escape_like_pattern(&escape_string(&s.to_lowercase()));
                            Ok(format!("toString({}) iLike '%{}%'", column_ref, escaped))
                        } else {
                            Ok(format!(
                                "toString({}) iLike concat('%', {}, '%')",
                                column_ref, value_sql
                            ))
                        }
                    }
                    Comparator::NotContains => {
                        if let Value::String(s) = value {
                            // NAN-1160: NOT iLike, never NOT hasTokenCaseInsensitive — the token
                            // form leaked sub-token matches through the exclusion filter.
                            let escaped = escape_like_pattern(&escape_string(&s.to_lowercase()));
                            Ok(format!(
                                "toString({}) NOT iLike '%{}%'",
                                column_ref, escaped
                            ))
                        } else {
                            Ok(format!(
                                "toString({}) NOT iLike concat('%', {}, '%')",
                                column_ref, value_sql
                            ))
                        }
                    }
                    Comparator::StartsWith => {
                        let pattern = match value {
                            Value::String(s) => {
                                // NAN-1160: escape_like_pattern so a literal `_`/`%` in the
                                // value is matched literally, not as an iLike wildcard.
                                format!(
                                    "'{}%'",
                                    escape_like_pattern(&escape_string(&s.to_lowercase()))
                                )
                            }
                            _ => format!("concat(lower({}), '%')", value_sql),
                        };
                        Ok(format!("toString({}) iLike {}", column_ref, pattern))
                    }
                    Comparator::NotStartsWith => {
                        let pattern = match value {
                            Value::String(s) => {
                                // NAN-1160: escape_like_pattern so a literal `_`/`%` in the
                                // value is matched literally, not as an iLike wildcard.
                                format!(
                                    "'{}%'",
                                    escape_like_pattern(&escape_string(&s.to_lowercase()))
                                )
                            }
                            _ => format!("concat(lower({}), '%')", value_sql),
                        };
                        Ok(format!("toString({}) NOT iLike {}", column_ref, pattern))
                    }
                    Comparator::EndsWith => {
                        let pattern = match value {
                            Value::String(s) => {
                                // NAN-1160: escape_like_pattern so a literal `_`/`%` in the
                                // value is matched literally, not as an iLike wildcard.
                                format!(
                                    "'%{}'",
                                    escape_like_pattern(&escape_string(&s.to_lowercase()))
                                )
                            }
                            _ => format!("concat('%', lower({}))", value_sql),
                        };
                        Ok(format!("toString({}) iLike {}", column_ref, pattern))
                    }
                    Comparator::NotEndsWith => {
                        let pattern = match value {
                            Value::String(s) => {
                                // NAN-1160: escape_like_pattern so a literal `_`/`%` in the
                                // value is matched literally, not as an iLike wildcard.
                                format!(
                                    "'%{}'",
                                    escape_like_pattern(&escape_string(&s.to_lowercase()))
                                )
                            }
                            _ => format!("concat('%', lower({}))", value_sql),
                        };
                        Ok(format!("toString({}) NOT iLike {}", column_ref, pattern))
                    }
                    Comparator::Eq | Comparator::Ne => {
                        // Case-insensitive string comparison
                        let sql_op = comparator_to_sql(op);
                        // NAN-2361: an array leaf needs membership. The pipeline
                        // `| where` path builds its own comparison, so the search-term
                        // arm's guard does not cover it — `| where file.hashes.value =
                        // "<sha256>"` was compiling to a scalar compare against the
                        // rendered whole array and silently matching nothing.
                        if self.where_scope_field_is_array(original_field, field) {
                            return Ok(self.array_membership_sql(&column_ref, sql_op, value));
                        }
                        match value {
                            Value::String(s) => {
                                // Boolean coercion: "true"/"false" → 1/0 for boolean fields (is_*, has_*, *_enabled, *_supported)
                                let lower = s.to_lowercase();
                                if (lower == "true" || lower == "false") && is_boolean_field(field)
                                {
                                    let bool_val = if lower == "true" { 1 } else { 0 };
                                    return Ok(format!("{} {} {}", column_ref, sql_op, bool_val));
                                }
                                // NAN-1634: a base-scan String column still
                                // carrying ingest values takes the index-form
                                // LHS — the predicate pushes down into the
                                // stage_0 read, where `lower(toString(col))`
                                // matched neither the raw blooms nor the
                                // `lower(col)` text indexes (31.8x read_rows
                                // on `* | where src_ip="…"` at Saturn scale).
                                // Computed/agg/Map names keep the
                                // scope-relative normalizing wrap. Eq ONLY —
                                // same rule as the OCSF alias path below: a
                                // raw Ne flips invariant-violating rows from
                                // excluded to included, and no skip index
                                // prunes a negation anyway.
                                if *op == Comparator::Eq
                                    && self.where_scope_physical_string_column(field)
                                {
                                    return Ok(format!(
                                        "{} {} '{}'",
                                        self.string_filter_lhs(field, &column_ref),
                                        sql_op,
                                        escape_string(&lower)
                                    ));
                                }
                                Ok(format!(
                                    "lower(toString({})) {} '{}'",
                                    column_ref,
                                    sql_op,
                                    escape_string(&lower)
                                ))
                            }
                            _ => Ok(format!("{} {} {}", column_ref, sql_op, value_sql)),
                        }
                    }
                    _ => {
                        // Numeric comparisons
                        let sql_op = comparator_to_sql(op);
                        // NAN-2361: a range against an array leaf needs ANY-element
                        // semantics for the same reason equality does -- a scalar
                        // compare runs against the rendered whole array and silently
                        // matches nothing. This is the form the rarity slider needs
                        // (`host_count <= N`).
                        if self.where_scope_field_is_array(original_field, field) {
                            return Ok(self.array_range_sql(&column_ref, sql_op, value));
                        }
                        // O44 (NAN-1721): when `column_ref` is a spans/metrics
                        // attribute Map access (the same guard that produced it
                        // above), a numeric range against its String value is
                        // otherwise String-vs-number → CH "no common type". Coerce
                        // both sides to Float64 (a non-numeric literal → NULL, so
                        // the row is excluded). Non-map targets (columns, computed/
                        // agg names) are untouched → byte-identical for logs.
                        if self.resolves_to_map_key(field) && !self.is_computed_field(field) {
                            let rhs = match value {
                                Value::String(s) if s.parse::<f64>().is_err() => {
                                    format!("toFloat64OrNull({})", value_sql)
                                }
                                Value::String(s) => s.clone(),
                                _ => value_sql.clone(),
                            };
                            return Ok(format!(
                                "toFloat64OrNull({}) {} {}",
                                column_ref, sql_op, rhs
                            ));
                        }
                        Ok(format!("{} {} {}", column_ref, sql_op, value_sql))
                    }
                }
            }
            SearchExpr::InList {
                field,
                values,
                negated,
            } => {
                // Check if field is an aggregation expression
                let column_ref = if field.contains('(') && field.contains(')') {
                    if let Some(func_end) = field.find('(') {
                        let func_name = &field[..func_end];
                        escape_identifier(func_name)
                    } else {
                        escape_identifier(field)
                    }
                } else if let Some(resolved) =
                    self.where_scope_schema_alias_expr(field, self.canonicalize_field(field))
                {
                    resolved
                } else {
                    escape_identifier(field)
                };

                if list_has_cidr(values) {
                    let canonical = self.canonicalize_field(field).to_string();
                    if let Some(sql) = self.cidr_in_list_predicate(&canonical, &column_ref, values, *negated, |exact| {
                        self.generate_where_condition(&SearchExpr::InList {
                            field: field.clone(),
                            values: exact.to_vec(),
                            negated: false,
                        })
                    })? {
                        return Ok(sql);
                    }
                }

                let op = if *negated { "NOT IN" } else { "IN" };
                // NAN-4276: numbers in a list against a String column are its
                // text values (`| where metadata.event_code IN (1, 7)`), as in
                // the Eq arm; a raw `IN (1, 7)` is a String/UInt8 type error.
                let text_operand = values.iter().any(|v| matches!(v, Value::Number(_)))
                    && self.where_scope_text_operand(field, self.canonicalize_field(field));
                // Case-insensitive for string values
                let all_strings = values.iter().all(|v| {
                    matches!(v, Value::String(_)) || (text_operand && matches!(v, Value::Number(_)))
                });
                if all_strings {
                    let values_sql: Vec<String> = values
                        .iter()
                        .map(|v| match v {
                            Value::String(s) => format!("'{}'", escape_string(&s.to_lowercase())),
                            Value::Number(_) => format!("'{}'", value_to_sql(v)),
                            _ => value_to_sql(v),
                        })
                        .collect();
                    let values_list = values_sql.join(", ");
                    // NAN-1634: same index-form selection as the Eq arm —
                    // a base-scan ingest-lowercased column compares RAW so
                    // its bloom/set index prunes; anything computed keeps the
                    // scope-relative `lower(...)`. Positive membership ONLY:
                    // a raw NOT IN flips invariant-violating rows from
                    // excluded to included, and no index prunes a negation.
                    let lhs = if !*negated && self.where_scope_physical_string_column(field) {
                        self.string_filter_lhs(field, &column_ref)
                    } else {
                        format!("lower({})", column_ref)
                    };
                    Ok(format!("{} {} ({})", lhs, op, values_list))
                } else {
                    let values_sql: Vec<String> = values.iter().map(value_to_sql).collect();
                    let values_list = values_sql.join(", ");
                    Ok(format!("{} {} ({})", column_ref, op, values_list))
                }
            }
            SearchExpr::FunctionFilter {
                function,
                op,
                value,
            } => {
                // Check if this is an aggregation function reference (e.g., avg(bytes_out) in WHERE after stats)
                // If so, use just the function name as the column reference
                let func_sql = if let EvalExpression::FunctionCall { name, args } = function {
                    // Check if it's an aggregation function
                    let agg_funcs = [
                        "count", "sum", "avg", "min", "max", "dc", "values", "list", "first",
                        "last", "earliest", "latest", "stdev", "var", "median", "perc95",
                    ];
                    if agg_funcs.contains(&name.to_lowercase().as_str()) && !args.is_empty() {
                        // This is an aggregation reference - use just the function name as column
                        escape_identifier(name)
                    } else {
                        // Regular function call
                        eval_expression_to_sql(self, function)?
                    }
                } else {
                    eval_expression_to_sql(self, function)?
                };

                let sql_op = comparator_to_sql(op);
                // Case-insensitive for string comparisons
                match (op, value) {
                    (Comparator::Eq | Comparator::Ne, Value::String(s)) => Ok(format!(
                        "lower({}) {} '{}'",
                        func_sql,
                        sql_op,
                        escape_string(&s.to_lowercase())
                    )),
                    _ => {
                        let value_sql = value_to_sql(value);
                        Ok(format!("{} {} {}", func_sql, sql_op, value_sql))
                    }
                }
            }
            SearchExpr::BooleanFunction(function) => eval_expression_to_sql(self, function),
            SearchExpr::EvalPredicate(expression) => typed_eval_expression_to_sql(self, expression),
            SearchExpr::FieldFunctionFilter {
                field,
                op,
                function,
            } => {
                // Check if field is an aggregation expression
                let column_ref = if field.contains('(') && field.contains(')') {
                    if let Some(func_end) = field.find('(') {
                        let func_name = &field[..func_end];
                        escape_identifier(func_name)
                    } else {
                        escape_identifier(field)
                    }
                } else {
                    escape_identifier(field)
                };

                let func_sql = eval_expression_to_sql(self, function)?;
                let sql_op = comparator_to_sql(op);
                // Case-insensitive for Eq/Ne. NAN-4286: `lower()` only takes a
                // String, so a numeric/time column (`http_response.code =
                // http_response.code`, an eval'd `c=404`) compared through it
                // was a chDB type error. Two typed scalars compare natively;
                // anything not proven String on both sides compares its text.
                let string_side = |name: &str| {
                    !self.is_upstream_computed_field(name)
                        && matches!(
                            self.resolved_field_type(name),
                            Some(crate::schema::FieldType::String)
                        )
                };
                let scalar_side = |name: &str| {
                    !self.is_upstream_computed_field(name) && self.field_is_non_string_scalar(name)
                };
                let rhs_field = match function {
                    EvalExpression::Field(name) => Some(name.as_str()),
                    _ => None,
                };
                match op {
                    Comparator::Eq | Comparator::Ne
                        if scalar_side(field) && rhs_field.is_some_and(scalar_side) =>
                    {
                        Ok(format!("{} {} {}", column_ref, sql_op, func_sql))
                    }
                    Comparator::Eq | Comparator::Ne
                        if string_side(field) && rhs_field.is_none_or(string_side) =>
                    {
                        Ok(format!("lower({}) {} lower({})", column_ref, sql_op, func_sql))
                    }
                    Comparator::Eq | Comparator::Ne => Ok(format!(
                        "lower(toString({})) {} lower(toString({}))",
                        column_ref, sql_op, func_sql
                    )),
                    _ => Ok(format!("{} {} {}", column_ref, sql_op, func_sql)),
                }
            }
            // NAN-4289 (F26): flat chains, as in the search expression.
            SearchExpr::And(..) => {
                let legs = and_chain_legs(expr)
                    .into_iter()
                    .map(|leg| self.generate_where_condition(leg))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(format!("({})", legs.join(" AND ")))
            }
            SearchExpr::Or(..) => {
                let legs = or_chain_legs(expr)
                    .into_iter()
                    .map(|leg| self.generate_where_condition(leg))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(format!("({})", legs.join(" OR ")))
            }
            SearchExpr::Not(inner) => {
                let inner_sql = self.generate_where_condition(inner)?;
                Ok(null_safe_not(&inner_sql))
            }
            SearchExpr::Group(inner) => {
                let inner_sql = self.generate_where_condition(inner)?;
                Ok(format!("({})", inner_sql))
            }
            SearchExpr::LiteralComparison { left, op, right } => {
                // Literal string comparison - case-insensitive for Eq/Ne
                let op_sql = comparator_to_sql(op);
                match (op, right) {
                    (Comparator::Eq | Comparator::Ne, Value::String(s)) => Ok(format!(
                        "lower('{}') {} '{}'",
                        escape_string(left),
                        op_sql,
                        escape_string(&s.to_lowercase())
                    )),
                    _ => {
                        let left_sql = format!("'{}'", escape_string(left));
                        let right_sql = value_to_sql(right);
                        Ok(format!("{} {} {}", left_sql, op_sql, right_sql))
                    }
                }
            }
            SearchExpr::InSubsearch {
                field,
                subsearch,
                negated,
                subsearch_dataset,
            } => self.generate_in_subsearch_filter(field, subsearch, *negated, *subsearch_dataset),
            // NAN-1580: same observable-anywhere expansion as the top-level arm.
            SearchExpr::IocMatch {
                values,
                feed,
                lookup,
            } => self.generate_ioc_match_filter(values, feed.as_ref(), lookup.as_ref()),
        }
    }

    /// Generate SQL for `field IN [search ... | return field]` subsearch expressions.
    /// Produces a ClickHouse subquery in one of three forms: bare numeric when
    /// BOTH sides are numeric under their profiles; bare String when BOTH sides
    /// are plain physical String columns (NAN-1634 — the `toString()` wrap is an
    /// identity there and only orphans the outer bloom skip index); otherwise
    /// the normalizing `toString(field) IN (SELECT DISTINCT toString(return_field)
    /// FROM ... LIMIT 10000)` coercion form (NAN-1562).
    ///
    /// NAN-1562: when `subsearch_dataset` selects a dataset whose storage table
    /// differs from the outer query's, the subsearch FROM table, time column,
    /// return-field resolution, and the subsearch's own search expression resolve
    /// against that dataset via a SCOPED clone (`with_dataset`) — the outer field
    /// (`field`) keeps resolving against `self`. The clone is local, so the
    /// sub-dataset never leaks into the outer pipeline's field resolution.
    fn generate_in_subsearch_filter(
        &self,
        field: &str,
        subsearch: &Query,
        negated: bool,
        subsearch_dataset: Option<crate::query::clickhouse_sql_gen::otel::Dataset>,
    ) -> Result<String, SqlGenError> {
        let time_range_guard = self
            .generation_time_range
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let time_range = time_range_guard.as_ref().ok_or_else(|| {
            SqlGenError::UnsupportedOperation(
                "Subsearch IN requires a time range context".to_string(),
            )
        })?;

        // NAN-1562: scope the subsearch to its own dataset. Cross-dataset only
        // when the subsearch targets a DIFFERENT dataset than the outer query —
        // `dataset=logs` from a logs query stays byte-identical. The clone shares
        // the Arc<profile> until `with_dataset` swaps it; its own
        // `generation_time_range` starts empty, so seed it from the outer range
        // for any nested subsearch resolution.
        // O8 (NAN-1721): compare by DATASET IDENTITY, not `table_name` strings —
        // an OCSF/tenant-prefixed logs table (`ocsf_logs` != `"logs"`) is NOT a
        // different dataset; the string form falsely flagged it cross-dataset and
        // re-pointed the sub at the wrong (`"logs"`) table (see `with_dataset`,
        // which now restores the captured `base_table` on a `Dataset::Logs` swap).
        let cross_dataset = subsearch_dataset
            .map(|ds| ds != self.dataset)
            .unwrap_or(false);
        let sub_gen_owned: Option<ClickHouseSqlGenerator> = if cross_dataset {
            let g = self.clone().with_dataset(subsearch_dataset.unwrap());
            match g.generation_time_range.write() {
                Ok(mut guard) => *guard = Some(time_range.clone()),
                Err(poisoned) => *poisoned.into_inner() = Some(time_range.clone()),
            }
            Some(g)
        } else {
            None
        };
        // `sub_gen` resolves the subsearch side (table, time column, return field,
        // search expr); `self` resolves the outer field.
        let sub_gen: &ClickHouseSqlGenerator = sub_gen_owned.as_ref().unwrap_or(self);

        // Walk the subsearch Query to extract the search expression and return fields
        let stages = self.collect_stages(subsearch);

        // This form compiles the subsearch's search predicate and optional
        // return field directly. Silently ignoring a stats/where/etc. stage
        // would turn a detection correlation into a different query.
        if stages.iter().any(|stage| matches!(stage,
            super::QueryStage::Command(command) if in_subsearch_return_fields(command).is_none()
        )) {
            return Err(SqlGenError::UnsupportedOperation(
                "IN subsearch supports only a search and an optional single return field \
                 (`| return f`, `| fields f` or `| table f`)"
                    .to_string(),
            ));
        }

        // Find the search expression (first stage)
        let search_expr = stages.iter().find_map(|s| match s {
            super::QueryStage::Search(expr) => Some(*expr),
            _ => None,
        });

        // Find the return command to get the target field(s)
        let return_fields: Vec<&str> = stages
            .iter()
            .filter_map(|s| match s {
                super::QueryStage::Command(command) => in_subsearch_return_fields(command),
                _ => None,
            })
            .flatten()
            .collect();

        // Determine which field to SELECT from the subsearch
        // Default to the outer field name if no return command specified
        let return_field = if return_fields.is_empty() {
            field
        } else {
            return_fields[0]
        };

        // NAN-1562 bound: a cross-dataset IN needs a usable key — the equality
        // bridge between the outer field and the subsearch return field. An empty
        // outer field has no column to compare against; reject with an actionable
        // error rather than emitting a nonsensical IN.
        if cross_dataset && field.trim().is_empty() {
            return Err(SqlGenError::UnsupportedOperation(
                "cross-dataset correlation requires a join key, e.g. \
                 `trace_id IN [dataset=logs … | return trace_id]`"
                    .to_string(),
            ));
        }

        // Build a single WHERE with the time range and the subsearch's search
        // expression — `optimize_move_to_prewhere` does placement (NAN-1412).
        // The time column is the SUBSEARCH dataset's (NAN-1562 fixes the
        // pre-existing hardcoded `timestamp` that was wrong for spans
        // `start_time`); a `dataset=risk` subsearch neutralizes the bound
        // entirely (fixed trailing windows baked into its derived base source,
        // NAN-1798 P2).
        let mut where_clause = sub_gen.time_bound_predicate(sub_gen.time_column(), time_range);
        if let Some(expr) = search_expr {
            let where_sql = sub_gen.generate_search_expr(expr)?;
            where_clause = format!("{} AND ({})", where_clause, where_sql);
        }

        // Build the SELECT expression for the return field against the SUBSEARCH
        // dataset (profile-aware: direct column for promoted/UDM columns, native
        // `event` subcolumn access for an OCSF tail path (NAN-1426),
        // `ext.{field}` for a UDM Unknown — byte-identical for UDM).
        let return_field_expr = sub_gen.field_access_expr(return_field, "String");

        // Build the outer field expression against the OUTER dataset (`self`).
        let outer_field_expr = self.field_access_expr(field, "String");

        let op = if negated { "NOT IN" } else { "IN" };

        // Comparison form per side's type (NAN-1562). The outer field is typed
        // under `self`'s profile; the RETURN field is typed under the SUBSEARCH
        // dataset's profile (`sub_gen`) — they can differ across datasets. The
        // numeric, no-coercion form is only safe when BOTH sides are numeric.
        // Otherwise compare as strings: previously `lower(<numeric col>)` was
        // emitted whenever the OUTER side was a string, which threw Code 43
        // (`lower` wants String) for `user IN [dataset=spans … | return
        // duration_ns]` (UInt64 sub side). `toString()` normalizes either type
        // to a comparable String without presuming the column is already String
        // (which `lower()` does).
        let outer_numeric = self.profile.is_numeric_field(field);
        let return_numeric = sub_gen.profile.is_numeric_field(return_field);
        if outer_numeric && return_numeric {
            Ok(format!(
                "{} {} (SELECT DISTINCT {} FROM {} WHERE {} LIMIT {})",
                outer_field_expr,
                op,
                return_field_expr,
                sub_gen.table_name,
                where_clause,
                SUBSEARCH_RESULT_LIMIT,
            ))
        } else if self.is_plain_string_physical_column(field)
            && sub_gen.is_plain_string_physical_column(return_field)
        {
            // NAN-1634: with BOTH sides plain physical String columns
            // (non-Nullable, DEFAULT '') the `toString()` wrap is a strict
            // identity that only orphans the outer column's
            // expression-matched bloom skip index (2.98x granules restored on
            // a 24h `src_ip IN [subsearch]`). The mixed-type sides the wrap
            // exists for (UUID / numeric-vs-string / Map / spill — the
            // NAN-1562 coercion cases) fail the gate and keep it.
            Ok(format!(
                "{} {} (SELECT DISTINCT {} FROM {} WHERE {} LIMIT {})",
                outer_field_expr,
                op,
                return_field_expr,
                sub_gen.table_name,
                where_clause,
                SUBSEARCH_RESULT_LIMIT,
            ))
        } else {
            Ok(format!(
                "toString({}) {} (SELECT DISTINCT toString({}) FROM {} WHERE {} LIMIT {})",
                outer_field_expr,
                op,
                return_field_expr,
                sub_gen.table_name,
                where_clause,
                SUBSEARCH_RESULT_LIMIT,
            ))
        }
    }
}

/// NAN-4284 (searchfuzz F20): the field an `IN [subsearch]` returns, named by
/// `| return f` or, as the nPL reference documents, by a single-field
/// `| fields f` / `| table f` (no alias, no wildcard). `None` for any other
/// stage, which the IN form refuses rather than silently ignore.
pub(crate) fn in_subsearch_return_fields(command: &Command) -> Option<Vec<&str>> {
    let plain = |name: &str| !name.contains('*');
    match command {
        Command::Return { fields, .. } => Some(fields.iter().map(String::as_str).collect()),
        Command::Fields { keep: true, fields } if fields.len() == 1 && plain(&fields[0]) => {
            Some(vec![fields[0].as_str()])
        }
        Command::Table { fields } if fields.len() == 1 && fields[0].alias.is_none() && plain(&fields[0].name) => {
            Some(vec![fields[0].name.as_str()])
        }
        _ => None,
    }
}

/// True when the RHS of a field filter compiles as a VALUE, never as a column
/// reference or an ambiguity error: every quoted RHS, every typed literal, and
/// every bareword that [`classify_rhs`] reads as a literal. For such a filter
/// the generated SQL is identical to the quoted spelling (codegen consults the
/// surface form only through `classify_rhs`), so a consumer outside this crate
/// -- the lean compiler's candidate hints (NAN-3162) -- may treat
/// `host=web1.corp.local` exactly like `host="web1.corp.local"`.
pub fn rhs_compiles_as_value(
    profile: &dyn crate::schema::SchemaProfile,
    field: &str,
    op: &Comparator,
    value: &Value,
    rhs_syntax: RhsSyntax,
) -> bool {
    classify_rhs(profile, field, op, value, rhs_syntax) == RhsReading::Literal
}

/// How the right-hand side of a `=` / `!=` field filter must be read
/// (NAN-2378 / NAN-2380).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RhsReading {
    /// An ordinary value. Every quoted RHS, every typed literal, and every bare
    /// token that does not name a field of the active profile.
    Literal,
    /// A reference to another column: a bare token that names a field, in a
    /// position where that cannot plausibly be a value.
    FieldReference,
    /// A bare token that names a field of the active profile on a profile where
    /// flat column names are ALSO everyday log values. Neither reading can be
    /// chosen without silently changing the meaning of a working query.
    Ambiguous,
}

/// NAN-3276: the legs of the maximal OR chain rooted at `expr`, left to
/// right, looking through grouping parentheses whose content is itself an OR
/// (`(a OR b) OR c` and `a OR (b OR c)` are the same disjunction). Iterative,
/// so a chain of any length costs no stack.
fn or_chain_legs(expr: &SearchExpr) -> Vec<&SearchExpr> {
    let mut legs = Vec::new();
    let mut pending = vec![expr];
    while let Some(next) = pending.pop() {
        match next {
            SearchExpr::Or(left, right) => {
                pending.push(right);
                pending.push(left);
            }
            SearchExpr::Group(inner) if matches!(**inner, SearchExpr::Or(..)) => {
                pending.push(inner);
            }
            leg => legs.push(leg),
        }
    }
    legs
}

/// NAN-4289: the legs of the maximal AND chain rooted at `expr`; the AND
/// counterpart of [`or_chain_legs`].
fn and_chain_legs(expr: &SearchExpr) -> Vec<&SearchExpr> {
    let mut legs = Vec::new();
    let mut pending = vec![expr];
    while let Some(next) = pending.pop() {
        match next {
            SearchExpr::And(left, right) => {
                pending.push(right);
                pending.push(left);
            }
            SearchExpr::Group(inner) if matches!(**inner, SearchExpr::And(..)) => {
                pending.push(inner);
            }
            leg => legs.push(leg),
        }
    }
    legs
}

/// Classify the RHS of a `=` / `!=` field filter. Single source of truth: query
/// VALIDATION calls it to reject an ambiguous comparison before execution (which
/// also covers the `| where` stages evaluated in Rust after a prevalence/risk
/// stage, where no SQL is ever generated), and CODEGEN calls it as the backstop
/// for every non-search path — detection rules, materialized views, dashboards.
pub(crate) fn classify_rhs(
    profile: &dyn crate::schema::SchemaProfile,
    field: &str,
    op: &Comparator,
    value: &Value,
    rhs_syntax: RhsSyntax,
) -> RhsReading {
    let ordering = matches!(
        op,
        Comparator::Gt | Comparator::Lt | Comparator::Gte | Comparator::Lte
    );
    if !ordering && !matches!(op, Comparator::Eq | Comparator::Ne) {
        return RhsReading::Literal;
    }
    let Value::String(rhs) = value else {
        return RhsReading::Literal;
    };
    // NAN-3329: `src_endpoint.port > dst_endpoint.port`. The parser resolves a
    // FLAT bare identifier after an ordering operator as a field itself; a
    // DOTTED one reached codegen as the string literal 'dst_endpoint.port'.
    // Ordering a column against a dotted schema path's spelling is never what
    // was meant, so a bare dotted path naming a known field is a reference.
    if ordering {
        let canonical_lhs =
            crate::query::clickhouse_sql_gen::canonicalize_field_for_profile(profile, field);
        // NAN-4286: `a > a` is a (degenerate) column comparison too, never
        // the dotted path's spelling.
        return if matches!(rhs_syntax, RhsSyntax::Bareword)
            && is_dotted_schema_path(rhs)
            && profile.is_known_field(rhs)
            && profile.is_known_field(canonical_lhs)
        {
            RhsReading::FieldReference
        } else {
            RhsReading::Literal
        };
    }
    // A QUOTED right-hand side is a value, full stop, on every profile.
    // `process.name != "process.file.name"` and `status = "disposition"` mean
    // the literal text, and saying so is possible only because the AST now
    // carries the surface form (NAN-2380).
    if !matches!(rhs_syntax, RhsSyntax::Bareword) {
        return RhsReading::Literal;
    }
    // Both sides must name real columns of the ACTIVE profile, so an ordinary
    // value (`status=Success`, `source_type=squid_proxy`) is never touched.
    if !profile.is_known_field(rhs) {
        return RhsReading::Literal;
    }
    let canonical_lhs =
        crate::query::clickhouse_sql_gen::canonicalize_field_for_profile(profile, field);
    if !profile.is_known_field(canonical_lhs) {
        return RhsReading::Literal;
    }
    // A schema-native DOTTED path (`process.file.name`, `src_endpoint.ip`) is
    // not a value that appears in logs, and on a strict-canonical profile a bare
    // token that is not a known field is rejected outright — so in both cases a
    // token that resolves is a field reference, not a literal.
    // NAN-4286: that includes the dotted self-comparison
    // `http_response.code = http_response.code`, which used to read as the
    // literal path text and matched nothing.
    if is_dotted_schema_path(rhs) {
        return RhsReading::FieldReference;
    }
    // A flat self-comparison (`user=user`) keeps its historical literal reading.
    if rhs == field {
        return RhsReading::Literal;
    }
    if profile.uses_strict_canonical_fields() {
        return RhsReading::FieldReference;
    }
    // A FLAT bare token on a permissive profile (UDM, OCSF 1.8 on ClickHouse).
    // `target_type=user`, `object=message` and `status=action` are all ordinary
    // log values that happen to spell column names.
    RhsReading::Ambiguous
}

/// The error an [`RhsReading::Ambiguous`] comparison must produce. One message,
/// shared by validation and codegen, naming BOTH readings and how to write each.
pub(crate) fn ambiguous_comparison_message(field: &str, op: &Comparator, rhs: &str) -> String {
    format!(
        "Ambiguous comparison '{field} {op} {rhs}': '{rhs}' is both a field of this \
         schema and a possible literal value, and an unquoted token does not say \
         which you mean. To compare the two FIELDS write '{field} {op} `{rhs}`' \
         (backticks quote a field reference) or \
         '| eval same = ({field} = {rhs}) | where same = true'. To compare against \
         the literal text write '{field} {op} \"{rhs}\"'.",
        op = op.as_str()
    )
}

/// NAN-4286 (F30): a time literal in any form `time_literal_sql`
/// accepts, as a UTC instant.
fn parse_time_literal(text: &str) -> Option<chrono::NaiveDateTime> {
    let text = text.trim();
    if let Ok(instant) = chrono::DateTime::parse_from_rfc3339(text) {
        return Some(instant.naive_utc());
    }
    for format in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(instant) = chrono::NaiveDateTime::parse_from_str(text, format) {
            return Some(instant);
        }
    }
    chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d")
        .ok()
        .and_then(|date| date.and_hms_opt(0, 0, 0))
}

/// True when `s` is shaped like a DOTTED schema path — the only literal shape
/// [`ClickHouseSqlGenerator::field_to_field_term`] will consider resolving as a
/// field reference (NAN-2378).
///
/// Requires at least one interior dot, ASCII identifier segments only, and no
/// wildcard/regex metacharacters. Deliberately stricter than
/// `validate_field_name_format`: this decides whether a token the user may have
/// meant as a VALUE is treated as a COLUMN, so anything that could plausibly be
/// a value (`10.0.0.1`, `cmd.exe*`, `a..b`, `.leading`) must fail here.
pub(crate) fn is_dotted_schema_path(s: &str) -> bool {
    let mut segments = 0;
    for segment in s.split('.') {
        segments += 1;
        let mut chars = segment.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    segments >= 2
}

/// Whether `field` is an `Array(T)` leaf of `profile` (directly, or through
/// the explicit column it resolves to). Shared by the SQL generator and the
/// lake count planner (NAN-4295) so both split the same by-fields.
pub(crate) fn profile_field_is_array(profile: &dyn crate::schema::SchemaProfile, field: &str) -> bool {
    if profile.field_type(field) == Some(crate::schema::FieldType::Array) {
        return true;
    }
    match profile.resolve(field) {
        crate::schema::FieldResolution::ExplicitColumn(column) => {
            profile.field_type(&column) == Some(crate::schema::FieldType::Array)
        }
        _ => false,
    }
}

/// NAN-4295: whether a schema `stats … by` field groups per element (the
/// generator's rule for a by-field no upstream stage computed).
pub(crate) fn stats_by_schema_field_is_array(profile: &dyn crate::schema::SchemaProfile, field: &str) -> bool {
    profile_field_is_array(profile, super::canonicalize_field_for_profile(profile, field))
}
