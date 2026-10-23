// SPDX-License-Identifier: AGPL-3.0-or-later

//! Single-keyword histograms from the v3 token counts (no scan of the groups
//! they cover).
//!
//! The search histogram companion of a bare keyword search is
//! `<kw> | timechart span=… count() as count`. Over a day of a common token
//! it scanned every row of the window (24 h `powershell`: ~13 s of chDB at
//! 3 vCPU), and its sum is the total the UI shows. Row groups written with v3
//! token indexes carry, for each token matching at least
//! `COUNT_THRESHOLD` of their rows, the exact number of matching rows per
//! minute ([`crate::parts::token_counts`]). For a group whose rows all lie
//! inside the query window, those minutes land in exactly the buckets the
//! SQL would put the rows in (every accepted span is a whole number of
//! minutes aligned to the epoch), so the group is answered from the index
//! and fenced out of the scan. Every other group (not v3, token not listed,
//! straddling a window edge) is scanned by the unchanged compiled SQL, and
//! the two bucket sets are added.
//!
//! Only the exact compiled shape below is served, recognized from the
//! compiler's SQL (not the nPL), so any other shape, or a compiler change,
//! keeps the scan:
//!
//! ```text
//! WITH stage_0 AS (SELECT … FROM __nano_lake_source__
//!   WHERE time >= '<start>' AND time < '<end>'
//!   AND ((hasAllTokens(lower(message), 't') OR hasAllTokens(lower(raw_data), 't')))),
//! stage_1 AS (SELECT <bucket>(time) AS time_bucket, count() AS <alias>
//!   FROM stage_0 GROUP BY time_bucket ORDER BY time_bucket)
//! SELECT * FROM stage_1 LIMIT <n> SETTINGS …
//! ```
//!
//! NAN-4311: `<kw> | stats count by metadata.log_source` (plain or as a
//! stats page) is served the same way from the source-family files of hour
//! parts: such a file's signed `log_sources` is exactly one source and every
//! one of its rows carries that source (the merge writes a row to a named
//! family only when its `metadata.log_source` equals the name; null and
//! unchosen sources go to the overflow file, whose `log_sources` is absent).
//! Its counted groups add to that source's group; groups of any other file
//! are scanned. The merge re-ranks every group the way the SQL does
//! (`count DESC, source ASC`). It needs every scanned group: when the scan's
//! page cut some off, it answers [`Merged::Rescan`] and the caller reruns
//! the plain scan (exact, just without the counts).

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

use crate::parts::sidecar::TokenGroup;
use crate::parts::token_counts::single_token;
use crate::planner::CompiledQuery;

/// A histogram (or scalar count) the counts can serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountPlan {
    /// The needle's single ClickHouse token.
    pub token: String,
    /// Bucket width in whole minutes (epoch-aligned); `0` for the scalar
    /// `<kw> | stats count` shape (one row, no time bucket).
    pub bucket_minutes: i64,
    /// The count column's name.
    pub alias: String,
    /// The SQL `LIMIT` (rows past it are dropped, as the SQL does).
    pub limit: usize,
    /// Half-open window `[from_us, to_us)`, µs (NAN-4280: the compiled bound
    /// is `time >= start AND time < end`).
    pub from_us: i64,
    pub to_us: i64,
    /// NAN-4311: `stats count by metadata.log_source` (then `bucket_minutes`
    /// is `0`); `None` for the scalar count and the histogram.
    pub by_source: Option<SourceGroups>,
}

/// NAN-4311: the grouped-by-source count's output contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceGroups {
    /// The compiler's stats page window `(offset, end)`: rows with ordinal 1
    /// or in `(offset, end]`, carrying `__nano_stats_total` and
    /// `__nano_stats_ordinal`. `None`: the plain ranked rows.
    pub page: Option<(usize, usize)>,
}

/// The source column of the grouped shape.
pub const SOURCE_FIELD: &str = "metadata.log_source";

/// Whether the per-request probe left the counts on (NAN-4311 knob
/// `keyword_counts`, default on): off scans exactly as without this module,
/// the parity baseline.
pub fn enabled() -> bool {
    crate::perf_overrides::probe_flag("keyword_counts", true)
}

/// NAN-4280: `WHERE <the compiler's half-open time bound>` with both
/// literals captured, built from the same function the compiler uses
/// ([`nanosiem_core::sql_hygiene::half_open_time_bound`]), so a change to
/// the bound's text can never silently stop the counts from engaging.
fn window_pattern() -> String {
    format!(r"WHERE {}\s*", nanosiem_core::sql_hygiene::half_open_time_bound_pattern("time", "[0-9: .-]+"))
}

fn shape() -> &'static regex::Regex {
    static SHAPE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SHAPE.get_or_init(|| {
        regex::Regex::new(&[
            r"^WITH stage_0 AS \(\s*SELECT [^\n()]* FROM __nano_lake_source__\s*",
            &window_pattern(),
            r"AND \(\(hasAllTokens\(lower\(message\), '([a-z0-9]+)'\) OR hasAllTokens\(lower\(raw_data\), '([a-z0-9]+)'\)\)\)\s*",
            r"\),\s*stage_1 AS \(\s*SELECT (toStartOfMinute|toStartOfFiveMinutes|toStartOfTenMinutes|toStartOfFifteenMinutes|toStartOfHour|toStartOfInterval)\(time(?:, INTERVAL ([0-9]+) (MINUTE|HOUR))?\) AS time_bucket, count\(\) AS ([A-Za-z_][A-Za-z0-9_]*)\s*",
            r"FROM stage_0\s*GROUP BY time_bucket\s*ORDER BY time_bucket\s*\)\s*",
            r"SELECT \* FROM stage_1 LIMIT ([0-9]+)(?: SETTINGS [^;\n]*)?\s*$",
        ].concat())
        .expect("static regex")
    })
}

/// NAN-4164: the scalar companion, `<kw> | stats count [as alias]`. Same
/// stage_0 as the histogram; stage_1 is one ungrouped `count()`.
fn scalar_shape() -> &'static regex::Regex {
    static SHAPE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SHAPE.get_or_init(|| {
        regex::Regex::new(&[
            r"^WITH stage_0 AS \(\s*SELECT [^\n()]* FROM __nano_lake_source__\s*",
            &window_pattern(),
            r"AND \(\(hasAllTokens\(lower\(message\), '([a-z0-9]+)'\) OR hasAllTokens\(lower\(raw_data\), '([a-z0-9]+)'\)\)\)\s*",
            r"\),\s*stage_1 AS \(\s*SELECT count\(\) AS ([A-Za-z_][A-Za-z0-9_]*)\s*",
            r"FROM stage_0\s*\)\s*",
            r"SELECT \* FROM stage_1 LIMIT ([0-9]+)(?: SETTINGS [^;\n]*)?\s*$",
        ].concat())
        .expect("static regex")
    })
}

/// NAN-4311: `<kw> | stats count [as alias] by metadata.log_source`, plain
/// or wrapped as the compiler's stats page.
fn source_shape() -> &'static regex::Regex {
    static SHAPE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SHAPE.get_or_init(|| {
        regex::Regex::new(&[
            r"^WITH stage_0 AS \(\s*SELECT [^\n()]* FROM __nano_lake_source__\s*",
            &window_pattern(),
            r"AND \(\(hasAllTokens\(lower\(message\), '([a-z0-9]+)'\) OR hasAllTokens\(lower\(raw_data\), '([a-z0-9]+)'\)\)\)\s*",
            r#"\),\s*stage_1 AS \(\s*SELECT "metadata\.log_source" AS "metadata\.log_source", count\(\) AS ([A-Za-z_][A-Za-z0-9_]*)\s*"#,
            r#"FROM stage_0\s*GROUP BY "metadata\.log_source"\s*\),\s*"#,
            r#"stage_2 AS \(\s*SELECT \* FROM stage_1\s*ORDER BY ([A-Za-z_][A-Za-z0-9_]*) DESC, "metadata\.log_source" ASC\s*\)\s*"#,
            r#"(?:,\s*__nano_stats_ranked AS \(\s*SELECT \*, count\(\) OVER \(\) AS __nano_stats_total, row_number\(\) OVER \(ORDER BY ([A-Za-z_][A-Za-z0-9_]*) DESC, "metadata\.log_source" ASC \) AS __nano_stats_ordinal FROM stage_2\s*\)\s*"#,
            r"SELECT \* FROM __nano_stats_ranked WHERE __nano_stats_ordinal = 1 OR \(__nano_stats_ordinal > ([0-9]+) AND __nano_stats_ordinal <= ([0-9]+)\) ORDER BY __nano_stats_ordinal|SELECT \* FROM stage_2)",
            r" LIMIT ([0-9]+)(?: SETTINGS [^;\n]*)?\s*$",
        ].concat())
        .expect("static regex")
    })
}

fn literal_us(literal: &str) -> Option<i64> {
    chrono::NaiveDateTime::parse_from_str(literal, "%Y-%m-%d %H:%M:%S%.f").ok().map(|time| time.and_utc().timestamp_micros())
}

/// The count plan of `compiled`, when its SQL is exactly the served shape
/// over the request window. `None` keeps the scan.
pub fn plan(compiled: &CompiledQuery, window: (i64, i64)) -> Option<CountPlan> {
    if compiled.dataset != "logs" {
        return None;
    }
    if let Some(captures) = scalar_shape().captures(&compiled.sql) {
        let (from_us, to_us) = (literal_us(&captures[1])?, literal_us(&captures[2])?);
        if (from_us, to_us) != window || from_us >= to_us {
            return None;
        }
        let token = single_token(&captures[3])?;
        if captures[4] != captures[3] || token != captures[3] {
            return None;
        }
        let limit = captures[6].parse().ok()?;
        return Some(CountPlan { token, bucket_minutes: 0, alias: captures[5].to_string(), limit, from_us, to_us, by_source: None });
    }
    if let Some(captures) = source_shape().captures(&compiled.sql) {
        let (from_us, to_us) = (literal_us(&captures[1])?, literal_us(&captures[2])?);
        if (from_us, to_us) != window || from_us >= to_us {
            return None;
        }
        let token = single_token(&captures[3])?;
        if captures[4] != captures[3] || token != captures[3] {
            return None;
        }
        // The ranking must order by this count (not another column).
        let alias = captures[5].to_string();
        if captures[6] != *alias || captures.get(7).is_some_and(|ranked| ranked.as_str() != alias) {
            return None;
        }
        let page = match (captures.get(8), captures.get(9)) {
            (Some(offset), Some(end)) => {
                let (offset, end) = (offset.as_str().parse::<usize>().ok()?, end.as_str().parse::<usize>().ok()?);
                (offset < end).then_some((offset, end))?;
                Some((offset, end))
            }
            (None, None) => None,
            _ => return None,
        };
        let limit = captures[10].parse().ok()?;
        return Some(CountPlan { token, bucket_minutes: 0, alias, limit, from_us, to_us, by_source: Some(SourceGroups { page }) });
    }
    let captures = shape().captures(&compiled.sql)?;
    let (from_us, to_us) = (literal_us(&captures[1])?, literal_us(&captures[2])?);
    if (from_us, to_us) != window || from_us >= to_us {
        return None;
    }
    let token = single_token(&captures[3])?;
    if captures[4] != captures[3] || token != captures[3] {
        return None;
    }
    let bucket_minutes = match (&captures[5], captures.get(6).map(|m| m.as_str()), captures.get(7).map(|m| m.as_str())) {
        ("toStartOfMinute", None, None) => 1,
        ("toStartOfFiveMinutes", None, None) => 5,
        ("toStartOfTenMinutes", None, None) => 10,
        ("toStartOfFifteenMinutes", None, None) => 15,
        ("toStartOfHour", None, None) => 60,
        // Epoch-aligned only when the width divides an hour (minutes) or a
        // day (hours); anything else keeps the scan.
        ("toStartOfInterval", Some(n), Some("MINUTE")) => n.parse::<i64>().ok().filter(|n| *n > 0 && 60 % n == 0)?,
        ("toStartOfInterval", Some(n), Some("HOUR")) => n.parse::<i64>().ok().filter(|n| *n > 0 && 24 % n == 0)? * 60,
        _ => return None,
    };
    let limit = captures[9].parse().ok()?;
    Some(CountPlan { token, bucket_minutes, alias: captures[8].to_string(), limit, from_us, to_us, by_source: None })
}

/// Rows the counts answered, per data file: by bucket start (unix seconds),
/// or by source for a grouped-by-source plan.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    files: BTreeMap<String, FileTally>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct FileTally {
    buckets: BTreeMap<i64, u64>,
    sources: BTreeMap<String, u64>,
    groups: usize,
}

impl Tally {
    /// Answer one row group of data file `file` from its counts: `Ok(true)`
    /// when counted (the group must then be fenced out of the scan),
    /// `Ok(false)` when it has to be scanned. `source` is the file's one
    /// signed source family (NAN-4311), required by a grouped-by-source plan.
    pub fn count_group(&mut self, file: &str, source: Option<&str>, plan: &CountPlan, group: &TokenGroup) -> Result<bool> {
        let Some(counts) = &group.counts else { return Ok(false) };
        if counts.rows == 0 || counts.min_time_us < plan.from_us || counts.max_time_us >= plan.to_us {
            return Ok(false);
        }
        if plan.by_source.is_some() && source.is_none() {
            return Ok(false);
        }
        let Some(minutes) = counts.lookup(plan.token.as_bytes())? else { return Ok(false) };
        let width = plan.bucket_minutes;
        let tally = self.files.entry(file.to_string()).or_default();
        match (&plan.by_source, source) {
            (Some(_), Some(source)) => {
                let rows = minutes.iter().map(|(_, rows)| u64::from(*rows)).sum::<u64>();
                *tally.sources.entry(source.to_string()).or_default() += rows;
            }
            _ => {
                for (minute, rows) in minutes {
                    // A scalar count has one bucket.
                    let bucket = if width == 0 { 0 } else { minute.div_euclid(width) * width * 60 };
                    *tally.buckets.entry(bucket).or_default() += u64::from(rows);
                }
            }
        }
        tally.groups += 1;
        Ok(true)
    }

    /// Drop a file's counts (its selection could not fence the counted
    /// groups out, so the scan reads them).
    pub fn forget(&mut self, file: &str) {
        self.files.remove(file);
    }

    pub fn buckets(&self) -> BTreeMap<i64, u64> {
        let mut out = BTreeMap::new();
        for tally in self.files.values() {
            for (bucket, rows) in &tally.buckets {
                *out.entry(*bucket).or_default() += rows;
            }
        }
        out
    }

    /// NAN-4311: counted rows per source.
    pub fn sources(&self) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for tally in self.files.values() {
            for (source, rows) in &tally.sources {
                *out.entry(source.clone()).or_default() += rows;
            }
        }
        out
    }

    pub fn groups(&self) -> usize {
        self.files.values().map(|tally| tally.groups).sum()
    }

    pub fn rows(&self) -> u64 {
        self.files.values().flat_map(|tally| tally.buckets.values().chain(tally.sources.values())).sum()
    }

    pub fn files(&self) -> impl Iterator<Item = &String> {
        self.files.keys()
    }
}

/// The merged answer, or a request to rerun the plain scan.
#[derive(Debug, Clone, PartialEq)]
pub enum Merged {
    Rows(Vec<Value>),
    /// NAN-4311: the scan's page cut groups the merge needs; rerun the
    /// statement without the counts.
    Rescan,
}

fn bucket_text(seconds: i64) -> Result<String> {
    Ok(chrono::DateTime::from_timestamp(seconds, 0).context("bucket time is out of range")?.format("%Y-%m-%d %H:%M:%S").to_string())
}

fn row_count(row: &Value, alias: &str) -> Result<u64> {
    let value = row.get(alias).context("histogram row has no count")?;
    value.as_u64().or_else(|| value.as_str().and_then(|text| text.parse().ok())).context("histogram count is not an integer")
}

/// The histogram rows: the scanned rows plus the counted buckets, in bucket
/// order, cut at the SQL limit. Scanned rows keep their own representation;
/// counted-only buckets use chDB's `DateTime` text and a JSON number.
pub fn merge(plan: &CountPlan, scanned: Vec<Value>, tally: &Tally) -> Result<Merged> {
    if let Some(groups) = &plan.by_source {
        return merge_sources(plan, groups, scanned, tally);
    }
    if plan.bucket_minutes == 0 {
        return merge_scalar(plan, scanned, tally).map(Merged::Rows);
    }
    let mut rows: BTreeMap<i64, Value> = BTreeMap::new();
    for row in scanned {
        let text = row.get("time_bucket").and_then(Value::as_str).context("histogram row has no time_bucket")?.to_string();
        let seconds = chrono::NaiveDateTime::parse_from_str(&text, "%Y-%m-%d %H:%M:%S")
            .with_context(|| format!("histogram bucket {text} is not a DateTime"))?
            .and_utc()
            .timestamp();
        if rows.insert(seconds, row).is_some() {
            bail!("histogram bucket {text} repeats");
        }
    }
    for (seconds, counted) in &tally.buckets() {
        match rows.get_mut(seconds) {
            Some(row) => {
                let total = row_count(row, &plan.alias)? + counted;
                let numeric = row[&plan.alias].is_number();
                row[&plan.alias] = if numeric { json!(total) } else { json!(total.to_string()) };
            }
            None => {
                let mut row = Map::new();
                row.insert("time_bucket".to_string(), json!(bucket_text(*seconds)?));
                row.insert(plan.alias.clone(), json!(counted));
                rows.insert(*seconds, Value::Object(row));
            }
        }
    }
    Ok(Merged::Rows(rows.into_values().take(plan.limit).collect()))
}

fn json_count(like: Option<&Value>, count: u64) -> Value {
    if like.is_some_and(Value::is_string) { json!(count.to_string()) } else { json!(count) }
}

/// NAN-4311: every source group (scanned plus counted), ranked as the SQL
/// ranks them (`count DESC, source ASC`, a null source last), then cut as
/// the SQL cuts them. Counted-only rows use the scanned rows' integer
/// representation (a JSON number when nothing was scanned).
fn merge_sources(plan: &CountPlan, groups: &SourceGroups, scanned: Vec<Value>, tally: &Tally) -> Result<Merged> {
    // The merge needs every scanned group. A plain scan proves that by
    // stopping short of its limit; a stats page by carrying every ordinal of
    // its exact cardinality.
    match groups.page {
        None if scanned.len() >= plan.limit => return Ok(Merged::Rescan),
        Some(_) => {
            let mut totals = scanned.iter().map(|row| row.get("__nano_stats_total").and_then(integer));
            let total = totals.next().flatten().unwrap_or(0);
            if scanned.iter().any(|row| row.get("__nano_stats_total").and_then(integer) != Some(total)) {
                bail!("stats page returned inconsistent cardinality");
            }
            if total != scanned.len() as u64 {
                return Ok(Merged::Rescan);
            }
        }
        None => {}
    }
    let like = scanned.iter().find_map(|row| row.get(&plan.alias)).cloned();
    let page_like = scanned.iter().find_map(|row| row.get("__nano_stats_total")).cloned();
    let mut ranked: BTreeMap<Option<String>, u64> = BTreeMap::new();
    for row in &scanned {
        let source = match row.get(SOURCE_FIELD) {
            None | Some(Value::Null) => None,
            Some(Value::String(source)) => Some(source.clone()),
            Some(other) => bail!("grouped count source is not a string: {other}"),
        };
        if ranked.insert(source, row_count(row, &plan.alias)?).is_some() {
            bail!("grouped count source repeats");
        }
    }
    for (source, counted) in tally.sources() {
        let total = ranked.entry(Some(source)).or_default();
        *total = total.checked_add(counted).context("count overflow")?;
    }
    let mut ranked = ranked.into_iter().collect::<Vec<_>>();
    // Bytewise source order (ClickHouse `String` order), a null source last.
    ranked.sort_by(|(left, left_count), (right, right_count)| {
        right_count.cmp(left_count).then_with(|| match (left, right) {
            (Some(left), Some(right)) => left.as_bytes().cmp(right.as_bytes()),
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
        })
    });
    let total = ranked.len() as u64;
    let rows = ranked.into_iter().enumerate().filter_map(|(index, (source, count))| {
        let ordinal = index + 1;
        let mut row = Map::new();
        row.insert(SOURCE_FIELD.to_string(), source.map_or(Value::Null, Value::String));
        row.insert(plan.alias.clone(), json_count(like.as_ref(), count));
        match groups.page {
            None => Some(Value::Object(row)),
            Some((offset, end)) => (ordinal == 1 || (ordinal > offset && ordinal <= end)).then(|| {
                row.insert("__nano_stats_total".to_string(), json_count(page_like.as_ref(), total));
                row.insert("__nano_stats_ordinal".to_string(), json_count(page_like.as_ref(), ordinal as u64));
                Value::Object(row)
            }),
        }
    });
    Ok(Merged::Rows(rows.take(plan.limit).collect()))
}

fn integer(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

/// The scalar count: the scan's one row (absent when nothing was left to
/// scan) plus every counted row, in the scan's representation.
fn merge_scalar(plan: &CountPlan, scanned: Vec<Value>, tally: &Tally) -> Result<Vec<Value>> {
    if scanned.len() > 1 {
        bail!("scalar count returned {} rows", scanned.len());
    }
    let counted = tally.rows();
    let row = match scanned.into_iter().next() {
        Some(mut row) => {
            let total = row_count(&row, &plan.alias)?.checked_add(counted).context("count overflow")?;
            let numeric = row[&plan.alias].is_number();
            row[&plan.alias] = if numeric { json!(total) } else { json!(total.to_string()) };
            row
        }
        None => json!({ plan.alias.clone(): counted }),
    };
    Ok(vec![row].into_iter().take(plan.limit).collect())
}

#[cfg(test)]
#[path = "keyword_count_native_tests.rs"]
mod native_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled(sql: &str) -> CompiledQuery {
        serde_json::from_value(json!({
            "schema_version": 1, "profile": "ocsf", "dataset": "logs", "source_placeholder": "__nano_lake_source__",
            "query_sha256": "x", "start": "2026-09-28T14:00:00Z", "end": "2026-09-29T14:00:00Z", "limit": 101,
            "table_view": false, "required_columns": [], "sql": sql,
        }))
        .unwrap()
    }

    fn sql(bucket: &str, token: &str) -> String {
        format!(
            "WITH stage_0 AS (\n  SELECT message, \"metadata.log_source\", \"metadata.uid\", raw_data, time FROM __nano_lake_source__\n  WHERE time >= '2026-09-28 14:00:00.000000' AND time < '2026-09-29 14:00:00.000000'\n  AND ((hasAllTokens(lower(message), '{token}') OR hasAllTokens(lower(raw_data), '{token}')))\n),\nstage_1 AS (\n  SELECT {bucket} AS time_bucket, count() AS count\n  FROM stage_0\n  GROUP BY time_bucket\n  ORDER BY time_bucket\n)\nSELECT * FROM stage_1 LIMIT 100001 SETTINGS max_threads=16, max_execution_time=300, optimize_read_in_order=1, optimize_aggregation_in_order=1"
        )
    }

    fn window() -> (i64, i64) {
        let at = |text: &str| chrono::DateTime::parse_from_rfc3339(text).unwrap().timestamp_micros();
        (at("2026-09-28T14:00:00Z"), at("2026-09-29T14:00:00Z"))
    }

    #[test]
    fn recognizes_only_the_single_token_histogram_shape() {
        let served = plan(&compiled(&sql("toStartOfFiveMinutes(time)", "powershell")) , window()).unwrap();
        assert_eq!(served, CountPlan { token: "powershell".into(), bucket_minutes: 5, alias: "count".into(), limit: 100_001, from_us: window().0, to_us: window().1, by_source: None });
        for (bucket, minutes) in [
            ("toStartOfMinute(time)", Some(1)),
            ("toStartOfTenMinutes(time)", Some(10)),
            ("toStartOfInterval(time, INTERVAL 30 MINUTE)", Some(30)),
            ("toStartOfHour(time)", Some(60)),
            ("toStartOfInterval(time, INTERVAL 3 HOUR)", Some(180)),
            ("toStartOfInterval(time, INTERVAL 7 MINUTE)", None),
            ("toStartOfInterval(time, INTERVAL 5 SECOND)", None),
            ("toStartOfInterval(time, INTERVAL 1 DAY)", None),
        ] {
            assert_eq!(plan_minutes(&sql(bucket, "powershell")), minutes, "{bucket}");
        }
        // Another window, a phrase needle or a second predicate: scan.
        assert!(plan(&compiled(&sql("toStartOfFiveMinutes(time)", "powershell")), (window().0 + 1, window().1)).is_none());
        assert!(plan(&compiled(&sql("toStartOfFiveMinutes(time)", "svchost.exe")) , window()).is_none());
        let two = sql("toStartOfFiveMinutes(time)", "powershell").replace("'powershell')))", "'powershell')) AND severity_id = 1)");
        assert!(plan(&compiled(&two) , window()).is_none());
        let mismatched = sql("toStartOfFiveMinutes(time)", "powershell").replacen("lower(raw_data), 'powershell'", "lower(raw_data), 'cmd'", 1);
        assert!(plan(&compiled(&mismatched) , window()).is_none());
        let by = sql("toStartOfFiveMinutes(time)", "powershell").replace("GROUP BY time_bucket", "GROUP BY time_bucket, x");
        assert!(plan(&compiled(&by) , window()).is_none());
    }

    fn scalar_sql(token: &str, alias: &str) -> String {
        format!(
            "WITH stage_0 AS (\n  SELECT message, \"metadata.log_source\", \"metadata.uid\", raw_data, time FROM __nano_lake_source__\n  WHERE time >= '2026-09-28 14:00:00.000000' AND time < '2026-09-29 14:00:00.000000'\n  AND ((hasAllTokens(lower(message), '{token}') OR hasAllTokens(lower(raw_data), '{token}')))\n),\nstage_1 AS (\n  SELECT count() AS {alias}\n  FROM stage_0\n)\nSELECT * FROM stage_1 LIMIT 100 SETTINGS max_threads=16, max_execution_time=300, optimize_read_in_order=0, optimize_aggregation_in_order=0"
        )
    }

    /// NAN-4164: `<kw> | stats count [as n]` is served like the histogram.
    #[test]
    fn recognizes_the_scalar_count_shape() {
        let served = plan(&compiled(&scalar_sql("sysmon", "count")), window()).unwrap();
        assert_eq!(served, CountPlan { token: "sysmon".into(), bucket_minutes: 0, alias: "count".into(), limit: 100, from_us: window().0, to_us: window().1, by_source: None });
        assert_eq!(plan(&compiled(&scalar_sql("sysmon", "n")), window()).unwrap().alias, "n");
        // Another window, a phrase, a second predicate or a grouped count: scan.
        assert!(plan(&compiled(&scalar_sql("sysmon", "count")), (window().0, window().1 - 1)).is_none());
        assert!(plan(&compiled(&scalar_sql("failed password", "count")), window()).is_none());
        let two = scalar_sql("sysmon", "count").replace("'sysmon')))", "'sysmon')) AND class_uid = 1007)");
        assert!(plan(&compiled(&two), window()).is_none());
        let grouped = scalar_sql("sysmon", "count").replace("FROM stage_0\n)", "FROM stage_0\n  GROUP BY \"device.hostname\"\n)");
        assert!(plan(&compiled(&grouped), window()).is_none());
        let mismatched = scalar_sql("sysmon", "count").replacen("lower(raw_data), 'sysmon'", "lower(raw_data), 'cmd'", 1);
        assert!(plan(&compiled(&mismatched), window()).is_none());
    }

    #[test]
    fn scalar_merge_adds_counted_rows_to_the_scanned_count() {
        let plan = CountPlan { token: "x".into(), bucket_minutes: 0, alias: "count".into(), limit: 100, from_us: 0, to_us: i64::MAX, by_source: None };
        let mut tally = Tally::default();
        tally.files.insert("a".into(), file_tally(BTreeMap::from([(0, 10)]), 2));
        tally.files.insert("b".into(), file_tally(BTreeMap::from([(0, 5)]), 1));
        assert_eq!(rows(merge(&plan, vec![json!({"count": 7})], &tally)), vec![json!({"count": 22})]);
        assert_eq!(rows(merge(&plan, vec![json!({"count": "7"})], &tally)), vec![json!({"count": "22"})]);
        // Everything counted: no scan row.
        assert_eq!(rows(merge(&plan, Vec::new(), &tally)), vec![json!({"count": 15})]);
        assert_eq!(rows(merge(&plan, Vec::new(), &Tally::default())), vec![json!({"count": 0})]);
        assert!(merge(&plan, vec![json!({"count": 1}), json!({"count": 2})], &tally).is_err());
    }

    fn file_tally(buckets: BTreeMap<i64, u64>, groups: usize) -> FileTally {
        FileTally { buckets, sources: BTreeMap::new(), groups }
    }

    fn rows(merged: Result<Merged>) -> Vec<Value> {
        match merged.unwrap() {
            Merged::Rows(rows) => rows,
            Merged::Rescan => panic!("unexpected rescan"),
        }
    }

    fn source_sql(token: &str, page: Option<(usize, usize)>) -> String {
        let stages = format!(
            "WITH stage_0 AS (\n  SELECT count, message, \"metadata.log_source\", \"metadata.uid\", raw_data, time FROM __nano_lake_source__\n  WHERE time >= '2026-09-28 14:00:00.000000' AND time < '2026-09-29 14:00:00.000000'\n  AND ((hasAllTokens(lower(message), '{token}') OR hasAllTokens(lower(raw_data), '{token}')))\n),\nstage_1 AS (\n  SELECT \"metadata.log_source\" AS \"metadata.log_source\", count() AS count\n  FROM stage_0\n  GROUP BY \"metadata.log_source\"\n),\nstage_2 AS (\n  SELECT * FROM stage_1\n  ORDER BY count DESC, \"metadata.log_source\" ASC\n)"
        );
        let settings = "SETTINGS max_threads=16, max_execution_time=300, optimize_read_in_order=0, optimize_aggregation_in_order=0";
        match page {
            None => format!("{stages}\nSELECT * FROM stage_2 LIMIT 100 {settings}"),
            Some((offset, end)) => format!(
                "{stages},\n__nano_stats_ranked AS (\n  SELECT *, count() OVER () AS __nano_stats_total, row_number() OVER (ORDER BY count DESC, \"metadata.log_source\" ASC ) AS __nano_stats_ordinal FROM stage_2\n)\nSELECT * FROM __nano_stats_ranked WHERE __nano_stats_ordinal = 1 OR (__nano_stats_ordinal > {offset} AND __nano_stats_ordinal <= {end}) ORDER BY __nano_stats_ordinal LIMIT {} {settings}",
                end - offset + usize::from(offset > 0)
            ),
        }
    }

    /// NAN-4311: `<kw> | stats count by metadata.log_source`, plain and as
    /// the stats page the engine compiles.
    #[test]
    fn recognizes_the_count_by_source_shapes() {
        let plain = plan(&compiled(&source_sql("svchost", None)), window()).unwrap();
        assert_eq!(plain, CountPlan { token: "svchost".into(), bucket_minutes: 0, alias: "count".into(), limit: 100, from_us: window().0, to_us: window().1, by_source: Some(SourceGroups { page: None }) });
        let paged = plan(&compiled(&source_sql("svchost", Some((0, 100)))), window()).unwrap();
        assert_eq!(paged.by_source, Some(SourceGroups { page: Some((0, 100)) }));
        assert_eq!(paged.limit, 100);
        let later = plan(&compiled(&source_sql("svchost", Some((40, 100)))), window()).unwrap();
        assert_eq!((later.by_source.unwrap().page, later.limit), (Some((40, 100)), 61));
        // Another window, a phrase, another group field, another ranking or
        // a second predicate: scan.
        assert!(plan(&compiled(&source_sql("svchost", None)), (window().0, window().1 - 1)).is_none());
        assert!(plan(&compiled(&source_sql("svchost.exe", None)), window()).is_none());
        let host = source_sql("svchost", Some((0, 100))).replace("metadata.log_source", "device.hostname");
        assert!(plan(&compiled(&host), window()).is_none());
        let ascending = source_sql("svchost", None).replace("count DESC", "count ASC");
        assert!(plan(&compiled(&ascending), window()).is_none());
        let two = source_sql("svchost", None).replace("'svchost')))", "'svchost')) AND class_uid = 1)");
        assert!(plan(&compiled(&two), window()).is_none());
        let headed = source_sql("svchost", None).replace("SELECT * FROM stage_2 LIMIT", "SELECT * FROM stage_2 LIMIT 5) SELECT * FROM stage_3 LIMIT");
        assert!(plan(&compiled(&headed), window()).is_none());
    }

    fn source_plan(page: Option<(usize, usize)>, limit: usize) -> CountPlan {
        CountPlan { token: "x".into(), bucket_minutes: 0, alias: "count".into(), limit, from_us: 0, to_us: i64::MAX, by_source: Some(SourceGroups { page }) }
    }

    fn source_tally(files: &[(&str, &str, u64)]) -> Tally {
        let mut tally = Tally::default();
        for (file, source, rows) in files {
            let entry = tally.files.entry(file.to_string()).or_default();
            *entry.sources.entry(source.to_string()).or_default() += rows;
            entry.groups += 1;
        }
        tally
    }

    #[test]
    fn source_merge_reranks_scanned_and_counted_groups() {
        let tally = source_tally(&[("a", "windows_sysmon", 100), ("b", "windows_event", 3), ("c", "windows_sysmon", 1)]);
        let scanned = vec![
            json!({"metadata.log_source": "windows_event", "count": 5}),
            json!({"metadata.log_source": "apache_access", "count": 8}),
            json!({"metadata.log_source": null, "count": 8}),
            json!({"metadata.log_source": "zeek_conn", "count": 8}),
        ];
        assert_eq!(rows(merge(&source_plan(None, 100), scanned.clone(), &tally)), vec![
            json!({"metadata.log_source": "windows_sysmon", "count": 101}),
            json!({"metadata.log_source": "apache_access", "count": 8}),
            json!({"metadata.log_source": "windows_event", "count": 8}),
            json!({"metadata.log_source": "zeek_conn", "count": 8}),
            json!({"metadata.log_source": null, "count": 8}),
        ]);
        // The SQL limit cuts the ranked groups; a scan that filled its
        // limit may have dropped groups: rescan.
        assert_eq!(rows(merge(&source_plan(None, 5), scanned[..3].to_vec(), &tally)).len(), 4);
        assert_eq!(merge(&source_plan(None, 4), scanned.clone(), &tally).unwrap(), Merged::Rescan);
        // Nothing scanned: counted groups only, as JSON numbers.
        assert_eq!(rows(merge(&source_plan(None, 100), Vec::new(), &tally)), vec![
            json!({"metadata.log_source": "windows_sysmon", "count": 101}),
            json!({"metadata.log_source": "windows_event", "count": 3}),
        ]);
        assert_eq!(rows(merge(&source_plan(None, 100), Vec::new(), &Tally::default())), Vec::<Value>::new());
        // Quoted integers stay quoted.
        assert_eq!(rows(merge(&source_plan(None, 100), vec![json!({"metadata.log_source": "windows_event", "count": "5"})], &tally))[0],
            json!({"metadata.log_source": "windows_sysmon", "count": "101"}));
        assert!(merge(&source_plan(None, 100), vec![scanned[0].clone(), scanned[0].clone()], &tally).is_err());
    }

    #[test]
    fn source_merge_renumbers_the_stats_page() {
        let tally = source_tally(&[("a", "b_src", 10), ("a", "c_src", 1)]);
        let page = |total: u64, rows: &[(&str, u64, u64)]| rows.iter().map(|(source, count, ordinal)| {
            json!({"metadata.log_source": source, "count": count, "__nano_stats_total": total, "__nano_stats_ordinal": ordinal})
        }).collect::<Vec<_>>();
        let scanned = page(2, &[("a_src", 7, 1), ("c_src", 2, 2)]);
        assert_eq!(rows(merge(&source_plan(Some((0, 100)), 100), scanned.clone(), &tally)), page(3, &[("b_src", 10, 1), ("a_src", 7, 2), ("c_src", 3, 3)]));
        // A later page keeps the cardinality carrier (ordinal 1).
        assert_eq!(rows(merge(&source_plan(Some((2, 100)), 99), scanned.clone(), &tally)), page(3, &[("b_src", 10, 1), ("c_src", 3, 3)]));
        // The scan's page lacks some of its groups: rescan.
        assert_eq!(merge(&source_plan(Some((0, 100)), 100), page(3, &[("a_src", 7, 1), ("c_src", 2, 2)]), &tally).unwrap(), Merged::Rescan);
        assert_eq!(merge(&source_plan(Some((1, 100)), 100), page(2, &[("a_src", 7, 1)]), &tally).unwrap(), Merged::Rescan);
        // Nothing scanned.
        assert_eq!(rows(merge(&source_plan(Some((0, 100)), 100), Vec::new(), &tally)), page(2, &[("b_src", 10, 1), ("c_src", 1, 2)]));
        assert!(merge(&source_plan(Some((0, 100)), 100), vec![scanned[0].clone(), json!({"metadata.log_source": "c_src", "count": 2, "__nano_stats_total": 3, "__nano_stats_ordinal": 2})], &tally).is_err());
    }

    #[test]
    fn a_source_plan_counts_only_groups_of_a_single_source_file() {
        use crate::parts::token_counts::CountBuilder;
        let mut builder = CountBuilder::new();
        for row in 0..20 {
            builder.start_row(60_000_000 * 10 + row);
            builder.add_text("svchost started");
        }
        let group = TokenGroup { rows: 20, tokens: 2, bitset: Vec::new(), saturated: false, blocks: None, counts: Some(builder.finish()), trigrams: None, pairs: None, addresses: false };
        let plan = CountPlan { token: "svchost".into(), ..source_plan(None, 100) };
        let mut tally = Tally::default();
        assert!(!tally.count_group("p/0", None, &plan, &group).unwrap());
        assert!(tally.count_group("p/1", Some("windows_sysmon"), &plan, &group).unwrap());
        assert_eq!(tally.sources(), BTreeMap::from([("windows_sysmon".to_string(), 20)]));
        assert_eq!((tally.groups(), tally.rows()), (1, 20));
        // The scalar and histogram plans do not need a source.
        let scalar = CountPlan { by_source: None, ..plan };
        assert!(tally.count_group("p/0", None, &scalar, &group).unwrap());
        assert_eq!(tally.buckets(), BTreeMap::from([(0, 20)]));
    }

    fn plan_minutes(sql: &str) -> Option<i64> {
        plan(&compiled(sql) , window()).map(|plan| plan.bucket_minutes)
    }

    #[test]
    fn merge_adds_counted_buckets_to_scanned_rows_in_order() {
        let plan = CountPlan { token: "x".into(), bucket_minutes: 5, alias: "count".into(), limit: 3, from_us: 0, to_us: i64::MAX, by_source: None };
        let scanned = vec![json!({"time_bucket": "2026-09-29 12:05:00", "count": 2})];
        let mut tally = Tally::default();
        let base = chrono::NaiveDateTime::parse_from_str("2026-09-29 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap().and_utc().timestamp();
        let buckets = BTreeMap::from([(base, 10), (base + 300, 5), (base + 600, 1), (base + 900, 1)]);
        tally.files.insert("a".into(), file_tally(buckets, 1));
        tally.files.insert("b".into(), file_tally(BTreeMap::from([(base, 3)]), 1));
        tally.forget("b");
        assert_eq!(rows(merge(&plan, scanned, &tally)), vec![
            json!({"time_bucket": "2026-09-29 12:00:00", "count": 10}),
            json!({"time_bucket": "2026-09-29 12:05:00", "count": 7}),
            json!({"time_bucket": "2026-09-29 12:10:00", "count": 1}),
        ]);
    }
}
