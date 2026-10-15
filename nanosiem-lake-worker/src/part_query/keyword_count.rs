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
//!   WHERE time BETWEEN '<start>' AND '<end>'
//!   AND ((hasAllTokens(lower(message), 't') OR hasAllTokens(lower(raw_data), 't')))),
//! stage_1 AS (SELECT <bucket>(time) AS time_bucket, count() AS <alias>
//!   FROM stage_0 GROUP BY time_bucket ORDER BY time_bucket)
//! SELECT * FROM stage_1 LIMIT <n> SETTINGS …
//! ```

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

use crate::parts::sidecar::TokenGroup;
use crate::parts::token_counts::single_token;
use crate::planner::CompiledQuery;

/// A histogram the counts can serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountPlan {
    /// The needle's single ClickHouse token.
    pub token: String,
    /// Bucket width in whole minutes (epoch-aligned).
    pub bucket_minutes: i64,
    /// The count column's name.
    pub alias: String,
    /// The SQL `LIMIT` (rows past it are dropped, as the SQL does).
    pub limit: usize,
    /// Inclusive window, µs.
    pub from_us: i64,
    pub to_us: i64,
}

fn shape() -> &'static regex::Regex {
    static SHAPE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SHAPE.get_or_init(|| {
        regex::Regex::new(concat!(
            r"^WITH stage_0 AS \(\s*SELECT [^\n()]* FROM __nano_lake_source__\s*",
            r"WHERE time BETWEEN '([0-9: .-]+)' AND '([0-9: .-]+)'\s*",
            r"AND \(\(hasAllTokens\(lower\(message\), '([a-z0-9]+)'\) OR hasAllTokens\(lower\(raw_data\), '([a-z0-9]+)'\)\)\)\s*",
            r"\),\s*stage_1 AS \(\s*SELECT (toStartOfMinute|toStartOfFiveMinutes|toStartOfTenMinutes|toStartOfFifteenMinutes|toStartOfHour|toStartOfInterval)\(time(?:, INTERVAL ([0-9]+) (MINUTE|HOUR))?\) AS time_bucket, count\(\) AS ([A-Za-z_][A-Za-z0-9_]*)\s*",
            r"FROM stage_0\s*GROUP BY time_bucket\s*ORDER BY time_bucket\s*\)\s*",
            r"SELECT \* FROM stage_1 LIMIT ([0-9]+)(?: SETTINGS [^;\n]*)?\s*$",
        ))
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
    let captures = shape().captures(&compiled.sql)?;
    let (from_us, to_us) = (literal_us(&captures[1])?, literal_us(&captures[2])?);
    if (from_us, to_us) != window || from_us > to_us {
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
    Some(CountPlan { token, bucket_minutes, alias: captures[8].to_string(), limit, from_us, to_us })
}

/// Rows the counts answered, per data file and bucket start (unix seconds).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    files: BTreeMap<String, (BTreeMap<i64, u64>, usize)>,
}

impl Tally {
    /// Answer one row group of data file `file` from its counts: `Ok(true)`
    /// when counted (the group must then be fenced out of the scan),
    /// `Ok(false)` when it has to be scanned.
    pub fn count_group(&mut self, file: &str, plan: &CountPlan, group: &TokenGroup) -> Result<bool> {
        let Some(counts) = &group.counts else { return Ok(false) };
        if counts.rows == 0 || counts.min_time_us < plan.from_us || counts.max_time_us > plan.to_us {
            return Ok(false);
        }
        let Some(minutes) = counts.lookup(plan.token.as_bytes())? else { return Ok(false) };
        let width = plan.bucket_minutes;
        let (buckets, groups) = self.files.entry(file.to_string()).or_default();
        for (minute, rows) in minutes {
            let bucket = minute.div_euclid(width) * width * 60;
            *buckets.entry(bucket).or_default() += u64::from(rows);
        }
        *groups += 1;
        Ok(true)
    }

    /// Drop a file's counts (its selection could not fence the counted
    /// groups out, so the scan reads them).
    pub fn forget(&mut self, file: &str) {
        self.files.remove(file);
    }

    pub fn buckets(&self) -> BTreeMap<i64, u64> {
        let mut out = BTreeMap::new();
        for (buckets, _) in self.files.values() {
            for (bucket, rows) in buckets {
                *out.entry(*bucket).or_default() += rows;
            }
        }
        out
    }

    pub fn groups(&self) -> usize {
        self.files.values().map(|(_, groups)| groups).sum()
    }

    pub fn rows(&self) -> u64 {
        self.files.values().flat_map(|(buckets, _)| buckets.values()).sum()
    }

    pub fn files(&self) -> impl Iterator<Item = &String> {
        self.files.keys()
    }
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
pub fn merge(plan: &CountPlan, scanned: Vec<Value>, tally: &Tally) -> Result<Vec<Value>> {
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
    Ok(rows.into_values().take(plan.limit).collect())
}

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
            "WITH stage_0 AS (\n  SELECT message, \"metadata.log_source\", \"metadata.uid\", raw_data, time FROM __nano_lake_source__\n  WHERE time BETWEEN '2026-09-28 14:00:00.000000' AND '2026-09-29 14:00:00.000000'\n  AND ((hasAllTokens(lower(message), '{token}') OR hasAllTokens(lower(raw_data), '{token}')))\n),\nstage_1 AS (\n  SELECT {bucket} AS time_bucket, count() AS count\n  FROM stage_0\n  GROUP BY time_bucket\n  ORDER BY time_bucket\n)\nSELECT * FROM stage_1 LIMIT 100001 SETTINGS max_threads=16, max_execution_time=300, optimize_read_in_order=1, optimize_aggregation_in_order=1"
        )
    }

    fn window() -> (i64, i64) {
        let at = |text: &str| chrono::DateTime::parse_from_rfc3339(text).unwrap().timestamp_micros();
        (at("2026-09-28T14:00:00Z"), at("2026-09-29T14:00:00Z"))
    }

    #[test]
    fn recognizes_only_the_single_token_histogram_shape() {
        let served = plan(&compiled(&sql("toStartOfFiveMinutes(time)", "powershell")) , window()).unwrap();
        assert_eq!(served, CountPlan { token: "powershell".into(), bucket_minutes: 5, alias: "count".into(), limit: 100_001, from_us: window().0, to_us: window().1 });
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

    fn plan_minutes(sql: &str) -> Option<i64> {
        plan(&compiled(sql) , window()).map(|plan| plan.bucket_minutes)
    }

    #[test]
    fn merge_adds_counted_buckets_to_scanned_rows_in_order() {
        let plan = CountPlan { token: "x".into(), bucket_minutes: 5, alias: "count".into(), limit: 3, from_us: 0, to_us: i64::MAX };
        let scanned = vec![json!({"time_bucket": "2026-09-29 12:05:00", "count": 2})];
        let mut tally = Tally::default();
        let base = chrono::NaiveDateTime::parse_from_str("2026-09-29 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap().and_utc().timestamp();
        let buckets = BTreeMap::from([(base, 10), (base + 300, 5), (base + 600, 1), (base + 900, 1)]);
        tally.files.insert("a".into(), (buckets, 1));
        tally.files.insert("b".into(), (BTreeMap::from([(base, 3)]), 1));
        tally.forget("b");
        let rows = merge(&plan, scanned, &tally).unwrap();
        assert_eq!(rows, vec![
            json!({"time_bucket": "2026-09-29 12:00:00", "count": 10}),
            json!({"time_bucket": "2026-09-29 12:05:00", "count": 7}),
            json!({"time_bucket": "2026-09-29 12:10:00", "count": 1}),
        ]);
    }
}
