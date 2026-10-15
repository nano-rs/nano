// SPDX-License-Identifier: AGPL-3.0-or-later

//! Host → IP over a search window on the lake (NAN-3294).
//!
//! Proxy and network events name the client only by address
//! (`src_endpoint.ip`, from conduit's `client_ip`), so a hostname filter such
//! as `device.hostname="ws-it-083.corp.local" | tree web` matched none of
//! them. This module resolves the host to the IPs it held over the window and
//! lets product views match those events by IP **at the times the host held
//! it** (DHCP churn hands the same address to other hosts).
//!
//! # Time correctness
//!
//! The window is cut into at most [`LAKE_HOST_IP_MAX_SAMPLES`] buckets of at
//! least five minutes. The identity index answers, in ONE bounded entity
//! batch, "which IP did host H hold at time t" (the newest observation at or
//! before t, at most [`LAKE_HOST_IP_MAX_AGE_HOURS`] old) at every bucket
//! boundary. An event in bucket `[t_i, t_{i+1})` from IP x belongs to H when
//! H held x at `t_i` or at `t_{i+1}` (a lease change inside the bucket keeps
//! both addresses for that bucket only). Consecutive buckets with the same
//! address merge into one binding `(host, ip, start, end)`.
//!
//! # Query shape
//!
//! Each binding becomes `(src_endpoint.ip="x" AND time>="a" AND time<"b")`,
//! OR-ed beside the analyst's host term. The bindings are plain nPL, so the
//! interactive lane and a durable tree job scan the same predicate, and the
//! tree note is derived from the query itself
//! ([`lake_tree_identity_bindings`]).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use chrono::{DateTime, Duration, NaiveDateTime, Utc};

use super::*;
use crate::auth::ScopeSet;
use crate::query::{Command, Comparator, Query, SearchExpr, TreePreset, Value};
use crate::search::lake::LakeIdentityEntityBatchItem;

/// Hosts one expansion resolves (one ≤ 500-item entity batch).
pub(crate) const LAKE_HOST_IP_MAX_HOSTS: usize = 4;
/// Buckets per host; the batch carries `buckets + 1` boundaries per host.
pub(crate) const LAKE_HOST_IP_MAX_SAMPLES: i64 = 96;
/// Smallest bucket.
const LAKE_HOST_IP_MIN_STEP_SECS: i64 = 300;
/// An index answer older than this at its boundary is not a binding.
pub(crate) const LAKE_HOST_IP_MAX_AGE_HOURS: i64 = 24;
/// More bindings than this are not inlined into a query.
pub(crate) const LAKE_HOST_IP_MAX_BINDINGS: usize = 64;

/// Host fields whose literal a tree/lateral expansion resolves to IPs.
pub(crate) const LAKE_HOST_FIELDS: &[&str] = &["device.hostname", "src_endpoint.hostname"];
/// The event field a binding matches: the client side of proxy/network events.
const LAKE_BINDING_IP_FIELD: &str = "src_endpoint.ip";
const LAKE_BINDING_TIME_FIELD: &str = "time";
const BINDING_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.6f";

/// One host → IP binding over `[start, end)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LakeHostIpBinding {
    pub host: String,
    pub ip: IpAddr,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Bucket boundaries over `[start, end]`, inclusive of both ends.
pub(crate) fn lake_host_ip_references(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Vec<DateTime<Utc>> {
    if end <= start {
        return vec![end];
    }
    let span_ms = (end - start).num_milliseconds().max(1);
    let buckets = ((span_ms / 1000 + LAKE_HOST_IP_MIN_STEP_SECS - 1) / LAKE_HOST_IP_MIN_STEP_SECS)
        .clamp(1, LAKE_HOST_IP_MAX_SAMPLES);
    (0..=buckets)
        .map(|index| start + Duration::milliseconds(span_ms * index / buckets))
        .collect()
}

/// Merge one host's boundary samples into bindings (see the module docs).
/// `samples` are `(boundary, ip held at that boundary)` in time order.
pub(crate) fn lake_host_ip_bindings(
    host: &str,
    samples: &[(DateTime<Utc>, Option<IpAddr>)],
) -> Vec<LakeHostIpBinding> {
    let mut out = Vec::new();
    if samples.len() < 2 {
        return out;
    }
    let mut open: BTreeMap<IpAddr, DateTime<Utc>> = BTreeMap::new();
    for bucket in 0..samples.len() - 1 {
        let (at, _) = samples[bucket];
        let allowed = [samples[bucket].1, samples[bucket + 1].1]
            .into_iter()
            .flatten()
            .collect::<BTreeSet<_>>();
        let closing = open
            .keys()
            .filter(|ip| !allowed.contains(ip))
            .copied()
            .collect::<Vec<_>>();
        for ip in closing {
            let start = open.remove(&ip).expect("open binding");
            out.push(LakeHostIpBinding {
                host: host.to_string(),
                ip,
                start,
                end: at,
            });
        }
        for ip in allowed {
            open.entry(ip).or_insert(at);
        }
    }
    // The window end is inclusive: an event stamped exactly at the last
    // boundary still belongs to the last bucket.
    let end = samples[samples.len() - 1].0 + Duration::seconds(1);
    for (ip, start) in open {
        out.push(LakeHostIpBinding {
            host: host.to_string(),
            ip,
            start,
            end,
        });
    }
    out.sort_by(|a, b| (a.start, a.ip).cmp(&(b.start, b.ip)));
    out
}

fn binding_time(at: DateTime<Utc>) -> String {
    at.format(BINDING_TIME_FORMAT).to_string()
}

fn parse_binding_time(value: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(value, BINDING_TIME_FORMAT)
        .ok()
        .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

/// The nPL text matching events by a host's bindings: each binding is
/// `(src_endpoint.ip="x" AND time>="a" AND time<"b")`, OR-ed.
pub(crate) fn lake_host_binding_npl(bindings: &[LakeHostIpBinding]) -> Option<String> {
    if bindings.is_empty() {
        return None;
    }
    let text = bindings
        .iter()
        .map(|binding| {
            format!(
                "({LAKE_BINDING_IP_FIELD}=\"{}\" AND {LAKE_BINDING_TIME_FIELD}>=\"{}\" AND {LAKE_BINDING_TIME_FIELD}<\"{}\")",
                binding.ip,
                binding_time(binding.start),
                binding_time(binding.end)
            )
        })
        .collect::<Vec<_>>()
        .join(" OR ");
    Some(text)
}

/// [`lake_host_binding_npl`] as a search expression.
pub(crate) fn lake_host_binding_expr(bindings: &[LakeHostIpBinding]) -> Option<SearchExpr> {
    let text = lake_host_binding_npl(bindings)?;
    match crate::query::parse_query(&text).ok()? {
        Query::Search(expr) => Some(expr),
        Query::Piped { .. } => None,
    }
}

/// The base search a terminal `tree web` scans, through the selection-only
/// stages (`head`/`where`/`sort`) a tree preview puts in front of it.
fn tree_web_base_search(query: &mut Query) -> Option<&mut SearchExpr> {
    fn base(query: &mut Query) -> Option<&mut SearchExpr> {
        match query {
            Query::Search(expr) => Some(expr),
            Query::Piped { source, command } => {
                matches!(
                    command,
                    Command::Head { .. } | Command::Where { .. } | Command::Sort { .. }
                )
                .then_some(())?;
                base(source)
            }
        }
    }
    let Query::Piped {
        source,
        command: Command::Tree {
            preset: Some(TreePreset::Web),
            ..
        },
    } = query
    else {
        return None;
    };
    base(source)
}

/// Exact host literal of a host term, or `None` (wildcards, regexes and
/// other comparisons are not resolved).
fn host_literal(expr: &SearchExpr) -> Option<String> {
    let SearchExpr::FieldFilter {
        field,
        op: Comparator::Eq,
        value,
        ..
    } = expr
    else {
        return None;
    };
    if !LAKE_HOST_FIELDS.contains(&field.as_str()) {
        return None;
    }
    let Value::String(value) = value else {
        return None;
    };
    let value = value.trim();
    (!value.is_empty() && !value.contains(['*', '?']) && value.parse::<IpAddr>().is_err())
        .then(|| value.to_ascii_lowercase())
}

/// The top-level conjuncts of a search (through groups of one term).
fn conjuncts_mut(expr: &mut SearchExpr) -> Vec<&mut SearchExpr> {
    let and_group =
        matches!(expr, SearchExpr::Group(inner) if matches!(**inner, SearchExpr::And(..)));
    if !and_group && !matches!(expr, SearchExpr::And(..)) {
        return vec![expr];
    }
    match expr {
        SearchExpr::And(left, right) => {
            let mut out = conjuncts_mut(left);
            out.extend(conjuncts_mut(right));
            out
        }
        SearchExpr::Group(inner) => conjuncts_mut(inner),
        _ => unreachable!("checked above"),
    }
}

fn unwrap_group(expr: &SearchExpr) -> &SearchExpr {
    match expr {
        SearchExpr::Group(inner) => unwrap_group(inner),
        other => other,
    }
}

/// NAN-3294: the hosts a terminal `tree web` is pinned to (an exact
/// `device.hostname` / `src_endpoint.hostname` term AND-ed into its base
/// search), lowercased and deduplicated. Empty when there is nothing to
/// resolve.
pub(crate) fn lake_tree_web_hosts(query: &Query) -> Vec<String> {
    let mut query = query.clone();
    let Some(expr) = tree_web_base_search(&mut query) else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    for conjunct in conjuncts_mut(expr) {
        if let Some(host) = host_literal(unwrap_group(conjunct)) {
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
    }
    hosts
}

/// NAN-3294: OR each pinned host term with the IP bindings of that host.
/// Returns how many host terms were widened.
pub(crate) fn expand_lake_tree_web_hosts(
    query: &mut Query,
    bindings: &[LakeHostIpBinding],
) -> usize {
    let Some(expr) = tree_web_base_search(query) else {
        return 0;
    };
    let mut widened = 0;
    for conjunct in conjuncts_mut(expr) {
        let Some(host) = host_literal(unwrap_group(conjunct)) else {
            continue;
        };
        let own = bindings
            .iter()
            .filter(|binding| binding.host == host)
            .cloned()
            .collect::<Vec<_>>();
        let Some(by_ip) = lake_host_binding_expr(&own) else {
            continue;
        };
        let original = std::mem::replace(conjunct, SearchExpr::Keyword(String::new()));
        *conjunct = SearchExpr::Group(Box::new(SearchExpr::Or(
            Box::new(SearchExpr::Group(Box::new(original))),
            Box::new(SearchExpr::Group(Box::new(by_ip))),
        )));
        widened += 1;
    }
    widened
}

/// NAN-3294: the host → IP bindings a widened `tree web` query carries
/// (the exact shape [`expand_lake_tree_web_hosts`] writes), with the host
/// each one widened. Read back from the query so the interactive lane and a
/// durable tree job describe the same expansion.
pub(crate) fn lake_tree_identity_bindings(query: &Query) -> Vec<LakeHostIpBinding> {
    fn binding(expr: &SearchExpr) -> Option<(IpAddr, DateTime<Utc>, DateTime<Utc>)> {
        let mut ip = None;
        let mut start = None;
        let mut end = None;
        fn terms<'a>(expr: &'a SearchExpr, out: &mut Vec<&'a SearchExpr>) {
            match expr {
                SearchExpr::And(left, right) => {
                    terms(left, out);
                    terms(right, out);
                }
                SearchExpr::Group(inner) => terms(inner, out),
                other => out.push(other),
            }
        }
        let mut parts = Vec::new();
        terms(expr, &mut parts);
        if parts.len() != 3 {
            return None;
        }
        for part in parts {
            let SearchExpr::FieldFilter {
                field, op, value, ..
            } = part
            else {
                return None;
            };
            let text = match value {
                Value::String(text) => text.clone(),
                Value::Ip(address) => address.to_string(),
                _ => return None,
            };
            match (field.as_str(), op) {
                (LAKE_BINDING_IP_FIELD, Comparator::Eq) => ip = text.parse().ok(),
                (LAKE_BINDING_TIME_FIELD, Comparator::Gte) => start = parse_binding_time(&text),
                (LAKE_BINDING_TIME_FIELD, Comparator::Lt) => end = parse_binding_time(&text),
                _ => return None,
            }
        }
        Some((ip?, start?, end?))
    }
    fn alternatives<'a>(expr: &'a SearchExpr, out: &mut Vec<&'a SearchExpr>) {
        match expr {
            SearchExpr::Or(left, right) => {
                alternatives(left, out);
                alternatives(right, out);
            }
            SearchExpr::Group(inner) if matches!(**inner, SearchExpr::Or(..)) => {
                alternatives(inner, out)
            }
            other => out.push(other),
        }
    }
    let mut query = query.clone();
    let Some(expr) = tree_web_base_search(&mut query) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for conjunct in conjuncts_mut(expr) {
        let mut options = Vec::new();
        alternatives(unwrap_group(conjunct), &mut options);
        let Some(host) = options
            .iter()
            .find_map(|option| host_literal(unwrap_group(option)))
        else {
            continue;
        };
        for option in options {
            if let Some((ip, start, end)) = binding(option) {
                out.push(LakeHostIpBinding {
                    host: host.clone(),
                    ip,
                    start,
                    end,
                });
            }
        }
    }
    out
}

/// The analyst-facing line naming the identities a widened tree used.
pub(crate) fn lake_host_binding_note(bindings: &[LakeHostIpBinding]) -> Option<String> {
    if bindings.is_empty() {
        return None;
    }
    let mut by_host: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for binding in bindings {
        by_host
            .entry(binding.host.as_str())
            .or_default()
            .push(format!(
                "{} ({}–{} UTC)",
                binding.ip,
                binding.start.format("%m-%d %H:%M"),
                binding.end.format("%m-%d %H:%M"),
            ));
    }
    let hosts = by_host
        .into_iter()
        .map(|(host, ips)| format!("{host} → {}", ips.join(", ")))
        .collect::<Vec<_>>()
        .join("; ");
    Some(format!(
        "Identities used: {hosts}. Events that carry only src_endpoint.ip (proxy, network) matched the host by IP during those times."
    ))
}

impl SearchService {
    /// Resolve `hosts` to the IPs they held over `[start, end]` (see the
    /// module docs): ONE bounded entity batch against the identity index.
    /// Errors when the index is unavailable or still backfilling; callers
    /// turn that into a visible warning, never a silent no-op.
    pub(crate) async fn resolve_lake_host_ip_bindings(
        &self,
        hosts: &[String],
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<Vec<LakeHostIpBinding>, SearchError> {
        if hosts.is_empty() {
            return Ok(Vec::new());
        }
        if hosts.len() > LAKE_HOST_IP_MAX_HOSTS {
            return Err(SearchError::SqlValidationError(format!(
                "host → IP resolution covers at most {LAKE_HOST_IP_MAX_HOSTS} hosts per search"
            )));
        }
        let client = self.lake_identity_client()?;
        let references = lake_host_ip_references(start, end);
        let items = hosts
            .iter()
            .flat_map(|host| {
                references
                    .iter()
                    .map(move |at| LakeIdentityEntityBatchItem {
                        value: host.to_ascii_lowercase(),
                        reference_time: at.to_rfc3339(),
                    })
            })
            .collect::<Vec<_>>();
        let answer = client
            .resolve_identity_entity_batch("host", &items, deny_source_types)
            .await?;
        if !answer.complete {
            return Err(SearchError::ServiceUnavailable(
                "host → IP resolution needs the tenant's identity observation index, which is still backfilling"
                    .to_string(),
            ));
        }
        let mut held: Vec<Option<IpAddr>> = vec![None; items.len()];
        for observation in answer.rows {
            let Some(item) = items.get(observation.ordinal) else {
                return Err(SearchError::SqlValidationError(
                    "lake identity worker returned an out-of-range ordinal".to_string(),
                ));
            };
            if observation.value != item.value {
                return Err(SearchError::SqlValidationError(
                    "lake identity worker substituted an entity binding".to_string(),
                ));
            }
            let reference = references[observation.ordinal % references.len()];
            let observed_at = super::lake_identity::parse_observed_at(&observation.observed_at)
                .ok_or_else(|| {
                    SearchError::SqlValidationError(
                        "lake identity answer has an invalid observation time".to_string(),
                    )
                })?;
            if observed_at > reference {
                return Err(SearchError::SqlValidationError(
                    "lake identity answer violates its point-in-time binding".to_string(),
                ));
            }
            if reference - observed_at > Duration::hours(LAKE_HOST_IP_MAX_AGE_HOURS) {
                continue;
            }
            held[observation.ordinal] = observation.ip.trim().parse().ok();
        }
        let mut bindings = Vec::new();
        for (host_index, host) in hosts.iter().enumerate() {
            let base = host_index * references.len();
            let samples = references
                .iter()
                .enumerate()
                .map(|(offset, at)| (*at, held[base + offset]))
                .collect::<Vec<_>>();
            bindings.extend(lake_host_ip_bindings(&host.to_ascii_lowercase(), &samples));
        }
        Ok(bindings)
    }

    /// NAN-3294: widen a lean `<host term> | tree web` to the host's IPs
    /// (see the module docs). Returns analyst-facing problems (resolution
    /// unavailable, no IP observed, too many bindings); the identities that
    /// were used are read back from the query by the tree builder.
    pub(super) async fn expand_lake_tree_web_query(
        &self,
        parsed: &mut Query,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        scope: &ScopeSet,
    ) -> Vec<String> {
        let hosts = lake_tree_web_hosts(parsed);
        if hosts.is_empty() {
            return Vec::new();
        }
        let listed = hosts.join(", ");
        let bindings = match self
            .resolve_lake_host_ip_bindings(&hosts, start, end, scope.deny_set())
            .await
        {
            Ok(bindings) => bindings,
            Err(error) => {
                tracing::warn!(error = %error, hosts = %listed, "tree web host → IP resolution unavailable");
                return vec![format!(
                    "Could not resolve {listed} to IP addresses ({error}). Proxy and network events carry only src_endpoint.ip, so they are not in this tree."
                )];
            }
        };
        if bindings.is_empty() {
            return vec![format!(
                "No IP address was observed for {listed} in this window. Proxy and network events carry only src_endpoint.ip, so they are not in this tree."
            )];
        }
        if bindings.len() > LAKE_HOST_IP_MAX_BINDINGS {
            return vec![format!(
                "{listed} held {} IP bindings in this window, more than the {LAKE_HOST_IP_MAX_BINDINGS} a search inlines. Narrow the time range to include proxy and network events.",
                bindings.len()
            )];
        }
        let widened = expand_lake_tree_web_hosts(parsed, &bindings);
        tracing::info!(hosts = %listed, bindings = bindings.len(), widened, "tree web host → IP expansion");
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{parse_query, PrettyPrint};

    fn at(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn references_are_bounded_and_cover_the_window() {
        let refs = lake_host_ip_references(at("2026-10-08T08:30:00Z"), at("2026-10-08T12:30:00Z"));
        assert_eq!(refs.len(), 49, "4h at 5 min");
        assert_eq!(refs[0], at("2026-10-08T08:30:00Z"));
        assert_eq!(*refs.last().unwrap(), at("2026-10-08T12:30:00Z"));
        let week = lake_host_ip_references(at("2026-10-01T00:00:00Z"), at("2026-10-08T00:00:00Z"));
        assert_eq!(week.len() as i64, LAKE_HOST_IP_MAX_SAMPLES + 1);
        assert!(
            LAKE_HOST_IP_MAX_HOSTS * week.len() <= 500,
            "one entity batch"
        );
        assert_eq!(
            lake_host_ip_references(at("2026-10-08T08:30:00Z"), at("2026-10-08T08:31:00Z")).len(),
            2
        );
    }

    #[test]
    fn dhcp_churn_splits_bindings_at_the_change() {
        let t = |m: i64| at("2026-10-08T12:00:00Z") + Duration::minutes(m);
        let samples = vec![
            (t(0), Some(ip("10.1.4.63"))),
            (t(5), Some(ip("10.1.4.63"))),
            (t(10), Some(ip("10.1.4.99"))),
            (t(15), Some(ip("10.1.4.99"))),
            (t(20), None),
        ];
        let bindings = lake_host_ip_bindings("ws-it-083.corp.local", &samples);
        assert_eq!(
            bindings,
            vec![
                LakeHostIpBinding { host: "ws-it-083.corp.local".into(), ip: ip("10.1.4.63"), start: t(0), end: t(10) },
                LakeHostIpBinding { host: "ws-it-083.corp.local".into(), ip: ip("10.1.4.99"), start: t(5), end: t(20) + Duration::seconds(1) },
            ],
            "the change bucket [5,10) keeps both addresses; the old one ends there, the new one runs to the inclusive end"
        );
        let steady = lake_host_ip_bindings(
            "h",
            &[(t(0), Some(ip("10.0.0.1"))), (t(5), Some(ip("10.0.0.1")))],
        );
        assert_eq!(steady.len(), 1);
        assert_eq!(
            steady[0].end,
            t(5) + Duration::seconds(1),
            "the window end is inclusive"
        );
        assert!(lake_host_ip_bindings("h", &[(t(0), None), (t(5), None)]).is_empty());
    }

    #[test]
    fn tree_web_host_terms_are_found_through_a_preview_head() {
        let mut query = parse_query(
            r#"device.hostname="WS-IT-083.corp.local" metadata.log_source=* | head 200 | tree web"#,
        )
        .unwrap();
        crate::search::query_processing::apply_profile_product_semantics(
            &mut query,
            &crate::schema::OcsfProfile::lake_1_9(),
        );
        assert_eq!(
            lake_tree_web_hosts(&query),
            vec!["ws-it-083.corp.local".to_string()]
        );
        for other in [
            r#"device.hostname="ws-*" | tree web"#,
            r#"device.hostname="ws-it-083" | tree process"#,
            r#"device.hostname="ws-it-083" | stats count"#,
            r#"device.hostname="ws-it-083" | eval x=1 | tree web"#,
        ] {
            assert!(
                lake_tree_web_hosts(&parse_query(other).unwrap()).is_empty(),
                "{other}"
            );
        }
    }

    #[test]
    fn expansion_ors_time_bound_ip_terms_and_reads_back() {
        let mut query =
            parse_query(r#"device.hostname="ws-it-083.corp.local" | tree web"#).unwrap();
        let t = |m: i64| at("2026-10-08T12:00:00Z") + Duration::minutes(m);
        let bindings = vec![
            LakeHostIpBinding {
                host: "ws-it-083.corp.local".into(),
                ip: ip("10.1.4.63"),
                start: t(0),
                end: t(240),
            },
            LakeHostIpBinding {
                host: "other".into(),
                ip: ip("10.9.9.9"),
                start: t(0),
                end: t(240),
            },
        ];
        assert_eq!(expand_lake_tree_web_hosts(&mut query, &bindings), 1);
        let text = query.pretty_print();
        assert!(
            text.contains(r#"device.hostname="ws-it-083.corp.local""#),
            "{text}"
        );
        assert!(text.contains(r#"src_endpoint.ip="10.1.4.63""#), "{text}");
        assert!(
            text.contains(r#"time>="2026-10-08 12:00:00.000000""#),
            "{text}"
        );
        assert!(
            text.contains(r#"time<"2026-10-08 16:00:00.000000""#),
            "{text}"
        );
        assert!(
            !text.contains("10.9.9.9"),
            "another host's binding never widens this term: {text}"
        );
        // The printed query (a durable job's stored post query) reads back.
        let reparsed = parse_query(&text).unwrap();
        assert_eq!(
            lake_tree_identity_bindings(&reparsed),
            vec![bindings[0].clone()]
        );
        let note = lake_host_binding_note(&lake_tree_identity_bindings(&reparsed)).unwrap();
        assert!(
            note.contains("ws-it-083.corp.local → 10.1.4.63 (10-08 12:00–10-08 16:00 UTC)"),
            "{note}"
        );
        assert!(lake_tree_identity_bindings(
            &parse_query(r#"device.hostname="x" | tree web"#).unwrap()
        )
        .is_empty());
    }
}
