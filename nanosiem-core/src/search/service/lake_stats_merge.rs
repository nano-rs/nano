// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact time-slice merge for `stats` pipelines the worker's scan fence
//! rejects (NAN-2361).
//!
//! The lake worker refuses a plan whose estimated scan exceeds
//! `min(max_query_bytes, max_memory_bytes)`. Single-`count` and `dc` stats
//! already recover by bisecting the time range; every other aggregation went
//! out as one request and failed closed forever once a tenant's window grew
//! past the fence (the enterprise-shared identity sync's 30-day
//! `stats count, earliest, latest, last(...) by user` never synced a user).
//!
//! This module extends the recovery to the aggregations whose per-slice
//! results merge EXACTLY over disjoint event-time slices:
//!
//! | nPL                                  | worker SQL                  | merge                     |
//! |--------------------------------------|-----------------------------|---------------------------|
//! | `count`                              | `count()`                   | sum                       |
//! | `earliest(timestamp)`, `min(timestamp)` | `min(timestamp)`         | min (chronological)       |
//! | `latest(timestamp)`, `max(timestamp)`   | `max(timestamp)`         | max (chronological)       |
//! | `first(f)`                           | `argMin(f, timestamp)`      | oldest slice's non-null   |
//! | `last(f)`                            | `argMax(f, timestamp)`      | newest slice's non-null   |
//!
//! `first`/`last` need no per-field companion timestamp: bisected slices are
//! disjoint in event time, so every event of a newer slice is strictly newer
//! than every event of an older one, and ClickHouse's `argMax`/`argMin` skip
//! rows whose value is NULL (a slice returns NULL only when the field is NULL
//! on all of its rows for that group). Hence "the newest slice whose `last(f)`
//! is non-null" is exactly the unsliced `argMax(f, timestamp)`; for a
//! non-Nullable column the value is never NULL and the rule degenerates to
//! "the newest slice that saw the group", which is also exact. A tie on
//! event time can only occur inside one slice, where the engine resolves it
//! exactly as the unsliced query would.
//!
//! `min`/`max` merge only on the physical event-time column: the worker's
//! JSON cannot distinguish a quoted UInt64 from a digit String, so merging
//! them for an arbitrary field could order `"10"` and `"9"` differently from
//! ClickHouse. Everything else (`avg`, `dc`, `values`, percentiles,
//! conditional or expression aggregations, a row transform before `stats`)
//! keeps the existing single-request behaviour.
//!
//! The path is taken ONLY after the worker rejects the unsliced request with
//! a scan-budget error, so every query that succeeds today is unchanged.

use std::collections::{BTreeMap, HashSet};
use std::future::Future;

use chrono::{DateTime, Utc};
use futures::StreamExt;

use super::core_search::{is_lake_scan_budget_rejection, LakeSliceRetries};
use crate::query::{AggFunc, Command, Query};
use crate::search::types::TimeRangeInput;
use crate::search::SearchError;

/// The raw-event time column the logs dataset compiles `first`/`last` against.
const EVENT_TIME_FIELD: &str = "timestamp";
/// Concurrent slice requests (same as the count / distinct slice paths).
const SLICE_CONCURRENCY: usize = 2;

/// How one aggregation's per-slice cells combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LakeSliceMerge {
    /// `count()` — sum.
    Count,
    /// `min`/`earliest` of the event time — chronological minimum.
    Earliest,
    /// `max`/`latest` of the event time — chronological maximum.
    Latest,
    /// `first(f)` — the oldest slice's non-null value.
    First,
    /// `last(f)` — the newest slice's non-null value.
    Last,
}

/// A `stats` pipeline that can run as disjoint time slices and merge exactly.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct LakeMergeableStatsPlan {
    /// `<search> | stats ...` — what each slice sends to the worker.
    pub aggregate_query: Query,
    pub group_by: Vec<String>,
    /// Output alias and merge rule, in the query's aggregation order.
    pub aggregations: Vec<(String, LakeSliceMerge)>,
    /// Row-local / ordering suffix applied in Rust to the merged set.
    pub post_commands: Vec<Command>,
}

fn merge_rule(aggregation: &crate::query::Aggregation) -> Option<LakeSliceMerge> {
    if aggregation.condition.is_some() || aggregation.field_expr.is_some() {
        return None;
    }
    let field = aggregation.field.as_deref();
    match (aggregation.func, field) {
        (AggFunc::Count, None) => Some(LakeSliceMerge::Count),
        (AggFunc::Earliest | AggFunc::Min, Some(EVENT_TIME_FIELD | "time")) => {
            Some(LakeSliceMerge::Earliest)
        }
        (AggFunc::Latest | AggFunc::Max, Some(EVENT_TIME_FIELD | "time")) => Some(LakeSliceMerge::Latest),
        (AggFunc::First, Some(_)) => Some(LakeSliceMerge::First),
        (AggFunc::Last, Some(_)) => Some(LakeSliceMerge::Last),
        _ => None,
    }
}

/// Recognise `<search> | stats <mergeable aggs> [by ...] [| suffix...]`.
///
/// The stats source must be the raw event search itself: a `where`/`eval`
/// before `stats` could rewrite the event-time column that `first`/`last`
/// order by. The suffix is limited to the bounded row/ordering commands the
/// count path already applies in Rust.
pub(super) fn lake_mergeable_stats_plan(query: &Query) -> Option<LakeMergeableStatsPlan> {
    let Query::Piped { source, command } = query else {
        return None;
    };
    if let (
        Query::Search(_),
        Command::Stats {
            aggregations,
            group_by,
        },
    ) = (source.as_ref(), command)
    {
        if aggregations.is_empty() {
            return None;
        }
        let group_by = group_by.clone().unwrap_or_default();
        let mut seen: HashSet<String> = group_by.iter().cloned().collect();
        if seen.len() != group_by.len() {
            return None;
        }
        let mut merged = Vec::with_capacity(aggregations.len());
        for aggregation in aggregations {
            let rule = merge_rule(aggregation)?;
            let alias = aggregation.output_alias();
            // A duplicate alias (or one shadowing a group key) would fold two
            // states into one JSON column; the worker's own output is then
            // ambiguous, so do not pretend to merge it.
            if !seen.insert(alias.clone()) {
                return None;
            }
            merged.push((alias, rule));
        }
        return Some(LakeMergeableStatsPlan {
            aggregate_query: query.clone(),
            group_by,
            aggregations: merged,
            post_commands: Vec::new(),
        });
    }
    let supported_suffix = matches!(
        command,
        Command::Where { .. }
            | Command::Head { .. }
            | Command::Tail { .. }
            | Command::Sort { .. }
            | Command::Table { .. }
            | Command::Dedup { .. }
            | Command::Rename { .. }
            | Command::Fields { .. }
            | Command::Fillnull { .. }
            | Command::Eval { .. }
    );
    if !supported_suffix {
        return None;
    }
    let mut plan = lake_mergeable_stats_plan(source)?;
    plan.post_commands.push(command.clone());
    Some(plan)
}

fn parse_event_time(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    let raw = match value {
        serde_json::Value::String(s) => s.trim().to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => return None,
    };
    if let Ok(dt) = DateTime::parse_from_rfc3339(&raw) {
        return Some(dt.with_timezone(&Utc));
    }
    for format in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&raw, format) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
        }
    }
    None
}

fn parse_count(value: Option<&serde_json::Value>) -> Option<u64> {
    let value = value?;
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
}

fn malformed(message: String) -> SearchError {
    SearchError::SqlValidationError(format!("sliced stats merge: {message}"))
}

/// Merge per-slice `stats` rows into the exact unsliced result.
///
/// Slices are ordered by `(start, end)` (a stable sort, so fully identical
/// ranges keep their input order); the merge is therefore independent of
/// completion order. Tie-break, defined for completeness although bisected
/// slices never overlap: `last` takes the newest-ordered non-null value,
/// `first` the oldest-ordered, and an equal earliest/latest timestamp keeps
/// the older slice's cell. Groups are emitted in key order.
pub(super) fn merge_lake_stats_slices(
    plan: &LakeMergeableStatsPlan,
    mut slices: Vec<(TimeRangeInput, Vec<serde_json::Value>)>,
    max_groups: usize,
) -> Result<Vec<serde_json::Value>, SearchError> {
    slices.sort_by(|left, right| (left.0.start, left.0.end).cmp(&(right.0.start, right.0.end)));
    // key -> (group values, per-aggregation cell)
    let mut merged = BTreeMap::<String, (Vec<serde_json::Value>, Vec<serde_json::Value>)>::new();
    for row in slices.into_iter().flat_map(|(_, rows)| rows) {
        let object = row
            .as_object()
            .ok_or_else(|| malformed("worker returned a non-object row".to_string()))?;
        let groups = plan
            .group_by
            .iter()
            .map(|field| {
                object
                    .get(field)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null)
            })
            .collect::<Vec<_>>();
        let key = serde_json::to_string(&groups)
            .map_err(|error| malformed(format!("group key could not be encoded: {error}")))?;
        if !merged.contains_key(&key) && merged.len() >= max_groups {
            return Err(SearchError::ResourceExhausted(format!(
                "sliced stats produced more than the configured bound of {max_groups} groups"
            )));
        }
        let entry = merged.entry(key).or_insert_with(|| {
            (
                groups,
                plan.aggregations
                    .iter()
                    .map(|(_, rule)| match rule {
                        LakeSliceMerge::Count => serde_json::Value::from(0_u64),
                        _ => serde_json::Value::Null,
                    })
                    .collect(),
            )
        });
        for ((alias, rule), cell) in plan.aggregations.iter().zip(entry.1.iter_mut()) {
            let incoming = object.get(alias).unwrap_or(&serde_json::Value::Null);
            match rule {
                LakeSliceMerge::Count => {
                    let add = parse_count(Some(incoming))
                        .ok_or_else(|| malformed(format!("worker omitted numeric {alias}")))?;
                    let total = parse_count(Some(cell))
                        .unwrap_or(0)
                        .checked_add(add)
                        .ok_or_else(|| malformed(format!("{alias} overflowed UInt64")))?;
                    *cell = serde_json::Value::from(total);
                }
                LakeSliceMerge::First => {
                    if cell.is_null() && !incoming.is_null() {
                        *cell = incoming.clone();
                    }
                }
                LakeSliceMerge::Last => {
                    if !incoming.is_null() {
                        *cell = incoming.clone();
                    }
                }
                LakeSliceMerge::Earliest | LakeSliceMerge::Latest => {
                    if incoming.is_null() {
                        continue;
                    }
                    if cell.is_null() {
                        *cell = incoming.clone();
                        continue;
                    }
                    let (Some(current), Some(candidate)) =
                        (parse_event_time(cell), parse_event_time(incoming))
                    else {
                        return Err(malformed(format!("{alias} is not a parseable event time")));
                    };
                    let replace = match rule {
                        LakeSliceMerge::Earliest => candidate < current,
                        _ => candidate > current,
                    };
                    if replace {
                        *cell = incoming.clone();
                    }
                }
            }
        }
    }
    Ok(merged
        .into_values()
        .map(|(groups, cells)| {
            let mut row = serde_json::Map::new();
            for (field, value) in plan.group_by.iter().zip(groups) {
                row.insert(field.clone(), value);
            }
            for ((alias, _), value) in plan.aggregations.iter().zip(cells) {
                row.insert(alias.clone(), value);
            }
            serde_json::Value::Object(row)
        })
        .collect())
}

/// Run a scan-budget-rejected stats query as bisected time slices.
///
/// `first_rejection` is the worker's verdict on `full_range`; the full range
/// is never re-sent. Each rejected slice is bisected again under the shared
/// [`LakeSliceRetries`] bounds (attempt cap, one-minute floor, and a stop
/// when a child's estimate does not shrink below 75% of its parent's), so a
/// query that cannot fit fails with the same bounded diagnostic as the count
/// path. Any non-budget error propagates unchanged. `run` receives the slice
/// path (for request ids) and the inclusive slice range.
pub(super) async fn run_lake_stats_slices<F, Fut>(
    full_range: &TimeRangeInput,
    first_rejection: SearchError,
    query_text: &str,
    run: F,
) -> Result<Vec<(TimeRangeInput, Vec<serde_json::Value>)>, SearchError>
where
    F: Fn(String, TimeRangeInput) -> Fut,
    Fut: Future<Output = Result<Vec<serde_json::Value>, SearchError>>,
{
    if !is_lake_scan_budget_rejection(&first_rejection) {
        return Err(first_rejection);
    }
    let mut retries = LakeSliceRetries::new();
    let (left, right) = retries.split("0", full_range, first_rejection, query_text)?;
    let mut pending = vec![("0l".to_string(), left), ("0r".to_string(), right)];
    let mut completed = Vec::new();
    while !pending.is_empty() {
        let attempts = futures::stream::iter(pending.drain(..).map(|(path, range)| {
            let response = run(path.clone(), range.clone());
            async move { (path, range, response.await) }
        }))
        .buffer_unordered(SLICE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
        for (path, range, response) in attempts {
            match response {
                Ok(rows) => completed.push((range, rows)),
                Err(error) if is_lake_scan_budget_rejection(&error) => {
                    let (left, right) = retries.split(&path, &range, error, query_text)?;
                    pending.push((format!("{path}l"), left));
                    pending.push((format!("{path}r"), right));
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(completed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    /// The exact nPL the enterprise-shared identity sync runs (kept literal so
    /// a drift in that query shows up here as a routing change).
    const IDENTITY_QUERY: &str = "user=* | stats count as events, \
         earliest(timestamp) as first_seen, latest(timestamp) as last_seen, \
         last(user_domain) as user_domain, last(user_identity_department) as department, \
         last(user_identity_email) as email \
         by user | sort -last_seen | head 50000";

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn range(start: &str, end: &str) -> TimeRangeInput {
        TimeRangeInput {
            start: t(start),
            end: t(end),
        }
    }

    fn fmt(ts: DateTime<Utc>) -> String {
        ts.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
    }

    #[test]
    fn identity_sync_query_has_an_exact_slice_merge_plan() {
        let plan = lake_mergeable_stats_plan(&parse_query(IDENTITY_QUERY).unwrap())
            .expect("identity sync stats must be sliceable");
        assert_eq!(plan.group_by, vec!["user".to_string()]);
        assert_eq!(
            plan.aggregations,
            vec![
                ("events".to_string(), LakeSliceMerge::Count),
                ("first_seen".to_string(), LakeSliceMerge::Earliest),
                ("last_seen".to_string(), LakeSliceMerge::Latest),
                ("user_domain".to_string(), LakeSliceMerge::Last),
                ("department".to_string(), LakeSliceMerge::Last),
                ("email".to_string(), LakeSliceMerge::Last),
            ]
        );
        assert_eq!(
            plan.post_commands.len(),
            2,
            "sort + head run over the merged set"
        );
        assert!(
            matches!(plan.aggregate_query, Query::Piped { ref command, .. } if matches!(*command, Command::Stats { .. }))
        );
        // The last-sign-in overlay query is sliceable too.
        assert!(lake_mergeable_stats_plan(
            &parse_query("user=* auth_result=success | stats latest(timestamp) as last_sign_in by user | head 50000").unwrap()
        )
        .is_some());
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn the_live_identity_sync_queries_are_slice_mergeable() {
        // Guards drift in `TenantIdentitySyncSettings`: if either query gains
        // an aggregation without an exact merge, it would silently fall back
        // to one unsliced request and fail closed again on a large tenant.
        let settings =
            crate::enterprise_shared_identity_sync::TenantIdentitySyncSettings::default();
        let observed =
            lake_mergeable_stats_plan(&parse_query(&settings.observed_users_query()).unwrap())
                .expect("observed-users query must be slice-mergeable");
        assert_eq!(
            observed.aggregations.len(),
            7,
            "count + earliest + latest + four OCSF identity attributes"
        );
        assert_eq!(observed.group_by, vec!["user.name".to_string()]);
        assert!(lake_mergeable_stats_plan(&parse_query(&settings.observed_principals_query(true)).unwrap()).is_some());
        assert!(
            lake_mergeable_stats_plan(&parse_query(&settings.last_sign_in_query()).unwrap())
                .is_some()
        );
    }

    #[test]
    fn non_mergeable_stats_never_take_the_slice_path() {
        for query in [
            // avg/dc/values have no exact slice-merge state here.
            "user=* | stats avg(bytes_in) by user",
            "user=* | stats dc(src_ip) by user",
            "user=* | stats values(src_ip) by user",
            // min/max on a non-time column: the worker's JSON cannot say whether
            // "10" < "9" is a String or a UInt64 comparison.
            "user=* | stats min(bytes_in) as b by user",
            // Conditional / expression aggregations.
            "user=* | stats count(eval(auth_result=\"success\")) as ok by user",
            // Duplicate output aliases would collapse two states into one column.
            "user=* | stats last(user_domain), last(user_identity_email) by user",
            // A row transform before stats could rewrite `timestamp`.
            "user=* | eval timestamp=0 | stats latest(timestamp) as l by user",
            // Not a stats pipeline at all.
            "user=* | head 10",
        ] {
            assert!(
                lake_mergeable_stats_plan(&parse_query(query).unwrap()).is_none(),
                "{query} must not be treated as slice-mergeable"
            );
        }
    }

    fn identity_plan() -> LakeMergeableStatsPlan {
        lake_mergeable_stats_plan(&parse_query(IDENTITY_QUERY).unwrap()).unwrap()
    }

    fn by_user(rows: Vec<Value>) -> BTreeMap<String, Value> {
        rows.into_iter()
            .map(|row| (row["user"].as_str().unwrap().to_string(), row))
            .collect()
    }

    #[test]
    fn merge_is_exact_across_slices_including_single_slice_users_and_null_tails() {
        let plan = identity_plan();
        let older = range("2026-09-01T00:00:00Z", "2026-09-10T23:59:59.999999Z");
        let newer = range("2026-09-11T00:00:00Z", "2026-09-20T00:00:00Z");
        let older_rows = vec![
            json!({"user": "alice", "events": "4", "first_seen": "2026-09-02 08:00:00.000000", "last_seen": "2026-09-09 08:00:00.000000",
                   "user_domain": "corp", "department": "SOC", "email": "alice@corp.example"}),
            // Seen ONLY in the older slice.
            json!({"user": "carol", "events": 2, "first_seen": "2026-09-03 01:00:00.000000", "last_seen": "2026-09-04 01:00:00.000000",
                   "user_domain": null, "department": "IT", "email": null}),
        ];
        let newer_rows = vec![
            // Newer slice: department NULL on every alice event here (argMax
            // skips NULLs), so the older slice's department is still the
            // latest non-null value; domain/email changed.
            json!({"user": "alice", "events": 3, "first_seen": "2026-09-12 00:00:00.000000", "last_seen": "2026-09-19 10:00:00.000000",
                   "user_domain": "corp2", "department": null, "email": "alice@new.example"}),
            // Seen ONLY in the newer slice.
            json!({"user": "bob", "events": 1, "first_seen": "2026-09-15 00:00:00.000000", "last_seen": "2026-09-15 00:00:00.000000",
                   "user_domain": "corp", "department": null, "email": "bob@corp.example"}),
        ];
        // Slice completion order is arbitrary (buffer_unordered): pass newer first.
        let merged = by_user(
            merge_lake_stats_slices(&plan, vec![(newer, newer_rows), (older, older_rows)], 1_000)
                .unwrap(),
        );
        assert_eq!(merged.len(), 3);
        let alice = &merged["alice"];
        assert_eq!(alice["events"], json!(7));
        assert_eq!(alice["first_seen"], json!("2026-09-02 08:00:00.000000"));
        assert_eq!(alice["last_seen"], json!("2026-09-19 10:00:00.000000"));
        assert_eq!(alice["user_domain"], json!("corp2"));
        assert_eq!(alice["email"], json!("alice@new.example"));
        assert_eq!(
            alice["department"],
            json!("SOC"),
            "null in the newest slice falls back to the newest non-null"
        );
        let carol = &merged["carol"];
        assert_eq!(carol["events"], json!(2));
        assert_eq!(carol["last_seen"], json!("2026-09-04 01:00:00.000000"));
        assert_eq!(carol["user_domain"], Value::Null);
        assert_eq!(carol["department"], json!("IT"));
        let bob = &merged["bob"];
        assert_eq!(bob["events"], json!(1));
        assert_eq!(bob["first_seen"], json!("2026-09-15 00:00:00.000000"));
        assert_eq!(bob["department"], Value::Null);
    }

    #[test]
    fn merge_tie_break_is_deterministic() {
        // Bisected slices are disjoint, so two slices can never both hold the
        // same event time. The merge still defines the tie-break so a tie can
        // never depend on completion order: slices are ordered by
        // (start, end); `last` takes the newest-ordered non-null value,
        // `first` the oldest-ordered, and equal earliest/latest timestamps
        // keep the older slice's cell. Identical ranges keep input order.
        let plan = lake_mergeable_stats_plan(
            &parse_query("user=* | stats first(user_domain) as f, last(user_domain) as l, latest(timestamp) as ts by user").unwrap(),
        )
        .unwrap();
        let a = range("2026-09-01T00:00:00Z", "2026-09-01T12:00:00Z");
        let b = range("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z");
        let row = |domain: &str| json!({"user": "u", "f": domain, "l": domain, "ts": "2026-09-01 06:00:00.000000"});
        for slices in [
            vec![(a.clone(), vec![row("a")]), (b.clone(), vec![row("b")])],
            vec![(b.clone(), vec![row("b")]), (a.clone(), vec![row("a")])],
        ] {
            let merged = merge_lake_stats_slices(&plan, slices, 10).unwrap();
            assert_eq!(merged.len(), 1);
            // `a` orders before `b` (same start, earlier end) regardless of input order.
            assert_eq!(merged[0]["f"], json!("a"));
            assert_eq!(merged[0]["l"], json!("b"));
            assert_eq!(merged[0]["ts"], json!("2026-09-01 06:00:00.000000"));
        }
        // Fully identical ranges: input order decides, first-listed is older.
        let same = vec![(a.clone(), vec![row("x")]), (a.clone(), vec![row("y")])];
        let merged = merge_lake_stats_slices(&plan, same, 10).unwrap();
        assert_eq!(
            (merged[0]["f"].clone(), merged[0]["l"].clone()),
            (json!("x"), json!("y"))
        );
    }

    #[test]
    fn merge_fails_closed_on_malformed_or_oversized_slices() {
        let plan = identity_plan();
        let r = range("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z");
        let bad_count =
            vec![json!({"user": "a", "events": "many", "first_seen": null, "last_seen": null})];
        assert!(merge_lake_stats_slices(&plan, vec![(r.clone(), bad_count)], 10).is_err());
        let bad_time =
            vec![json!({"user": "a", "events": 1, "first_seen": "yesterday", "last_seen": null})];
        let two = vec![(r.clone(), bad_time.clone()), (r.clone(), bad_time)];
        assert!(merge_lake_stats_slices(&plan, two, 10).is_err());
        let many = (0..3)
            .map(|i| json!({"user": format!("u{i}"), "events": 1}))
            .collect();
        assert!(matches!(
            merge_lake_stats_slices(&plan, vec![(r, many)], 2),
            Err(SearchError::ResourceExhausted(_))
        ));
    }

    /// One synthetic lake event.
    #[derive(Clone)]
    struct Event {
        ts: DateTime<Utc>,
        user: &'static str,
        domain: Option<&'static str>,
        department: Option<&'static str>,
        email: Option<&'static str>,
    }

    /// Reference aggregate over `events` inside `range`, with ClickHouse
    /// semantics: count(), min/max(timestamp), argMax(x, timestamp) skipping
    /// NULL `x`. Events never share a timestamp per user here, so argMax is
    /// deterministic and the reference is exact.
    fn aggregate(events: &[Event], range: &TimeRangeInput) -> Vec<Value> {
        let mut groups: BTreeMap<&str, Vec<&Event>> = BTreeMap::new();
        for event in events
            .iter()
            .filter(|e| e.ts >= range.start && e.ts <= range.end)
        {
            groups.entry(event.user).or_default().push(event);
        }
        groups
            .into_iter()
            .map(|(user, mut rows)| {
                rows.sort_by_key(|e| e.ts);
                let last = |pick: fn(&Event) -> Option<&'static str>| {
                    rows.iter()
                        .rev()
                        .find_map(|e| pick(e))
                        .map_or(Value::Null, |v| json!(v))
                };
                json!({
                    "user": user,
                    // UInt64 arrives quoted from the worker's JSON.
                    "events": rows.len().to_string(),
                    "first_seen": fmt(rows.first().unwrap().ts),
                    "last_seen": fmt(rows.last().unwrap().ts),
                    "user_domain": last(|e| e.domain),
                    "department": last(|e| e.department),
                    "email": last(|e| e.email),
                })
            })
            .collect()
    }

    fn synthetic_events() -> Vec<Event> {
        let base = Utc.with_ymd_and_hms(2026, 8, 23, 0, 0, 0).unwrap();
        let mut events = Vec::new();
        // alice: active the whole window; department disappears from her
        // newest events (NULL tail), email changes near the end.
        for i in 0..240 {
            events.push(Event {
                ts: base + Duration::hours(3 * i) + Duration::seconds(7),
                user: "alice",
                domain: Some("corp"),
                department: (i < 150).then_some(if i < 60 { "IT" } else { "SOC" }),
                email: Some(if i < 200 {
                    "alice@corp.example"
                } else {
                    "alice@new.example"
                }),
            });
        }
        // bob: only in the first few days.
        for i in 0..5 {
            events.push(Event {
                ts: base + Duration::hours(10 + i) + Duration::milliseconds(250),
                user: "bob",
                domain: None,
                department: Some("HR"),
                email: None,
            });
        }
        // dave: one event on each side of the first bisection point (the
        // left slice ends 1 µs before the right one starts).
        for ts in [
            base + Duration::days(15) - Duration::microseconds(1),
            base + Duration::days(15),
        ] {
            events.push(Event {
                ts,
                user: "dave",
                domain: Some("edge"),
                department: None,
                email: None,
            });
        }
        // carol: a single event on the last day.
        events.push(Event {
            ts: base + Duration::days(29) + Duration::minutes(1),
            user: "carol",
            domain: Some("ext"),
            department: None,
            email: Some("carol@ext.example"),
        });
        events
    }

    #[tokio::test]
    async fn over_budget_query_completes_via_slices_and_matches_the_unsliced_aggregate() {
        let plan = identity_plan();
        let events = synthetic_events();
        let full = TimeRangeInput {
            start: Utc.with_ymd_and_hms(2026, 8, 23, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 9, 22, 0, 0, 0).unwrap(),
        };
        // Fake reader: the estimate is proportional to the events in range and
        // anything above the budget is rejected before execution, exactly like
        // the worker's interactive fence.
        const BYTES_PER_EVENT: u64 = 8_000_000;
        const BUDGET: u64 = 536_870_912;
        let estimate = |range: &TimeRangeInput| {
            events
                .iter()
                .filter(|e| e.ts >= range.start && e.ts <= range.end)
                .count() as u64
                * BYTES_PER_EVENT
        };
        let full_estimate = estimate(&full);
        assert!(
            full_estimate > BUDGET,
            "fixture must exceed the budget ({full_estimate})"
        );
        let calls = std::sync::Mutex::new(Vec::<(String, bool)>::new());
        let reader = |path: String, range: TimeRangeInput| {
            let estimated = estimate(&range);
            let rejected = estimated > BUDGET;
            calls.lock().unwrap().push((path, rejected));
            let rows = aggregate(&events, &range);
            async move {
                if rejected {
                    Err(SearchError::ResourceExhausted(format!(
                        "scan; estimated_bytes={estimated}; budget_bytes={BUDGET}"
                    )))
                } else {
                    Ok(rows)
                }
            }
        };
        let first_rejection = SearchError::ResourceExhausted(format!(
            "scan; estimated_bytes={full_estimate}; budget_bytes={BUDGET}"
        ));
        let slices = run_lake_stats_slices(&full, first_rejection, IDENTITY_QUERY, reader)
            .await
            .expect("an over-budget stats query must complete through slices");
        assert!(slices.len() >= 2);
        let calls = calls.into_inner().unwrap();
        assert!(
            calls.iter().all(|(path, _)| path != "0"),
            "the rejected full range is not re-sent"
        );
        // Slices tile the window exactly: disjoint, gap-free, inclusive.
        let mut ranges: Vec<_> = slices.iter().map(|(r, _)| r.clone()).collect();
        ranges.sort_by_key(|r| r.start);
        assert_eq!(ranges.first().unwrap().start, full.start);
        assert_eq!(ranges.last().unwrap().end, full.end);
        for pair in ranges.windows(2) {
            assert_eq!(pair[0].end + Duration::microseconds(1), pair[1].start);
        }
        let merged = by_user(merge_lake_stats_slices(&plan, slices, 1_000).unwrap());
        let mut expected = by_user(aggregate(&events, &full));
        for row in expected.values_mut() {
            let n: u64 = row["events"].as_str().unwrap().parse().unwrap();
            row["events"] = json!(n);
        }
        assert_eq!(merged, expected);
        assert_eq!(merged["alice"]["department"], json!("SOC"));
        assert_eq!(merged["alice"]["email"], json!("alice@new.example"));
        assert_eq!(merged["bob"]["user_domain"], Value::Null);
        assert_eq!(merged["carol"]["events"], json!(1));
        assert_eq!(
            merged["dave"]["events"],
            json!(2),
            "boundary events counted exactly once"
        );
    }

    #[tokio::test]
    async fn slicing_stops_when_estimates_do_not_shrink() {
        let full = range("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z");
        let reader = |_path: String, _range: TimeRangeInput| async {
            Err::<Vec<Value>, _>(SearchError::ResourceExhausted(
                "scan; estimated_bytes=900000000; budget_bytes=536870912".into(),
            ))
        };
        let error = run_lake_stats_slices(
            &full,
            SearchError::ResourceExhausted(
                "scan; estimated_bytes=900000000; budget_bytes=536870912".into(),
            ),
            IDENTITY_QUERY,
            reader,
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("stopped after scheduling"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn non_budget_errors_propagate_unchanged() {
        let full = range("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z");
        let reader = |_path: String, _range: TimeRangeInput| async {
            Err::<Vec<Value>, _>(SearchError::ServiceUnavailable("worker down".into()))
        };
        let error = run_lake_stats_slices(
            &full,
            SearchError::ResourceExhausted(
                "scan; estimated_bytes=900000000; budget_bytes=536870912".into(),
            ),
            IDENTITY_QUERY,
            reader,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, SearchError::ServiceUnavailable(_)));
    }
}
