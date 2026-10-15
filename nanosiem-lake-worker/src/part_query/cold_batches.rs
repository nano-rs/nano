// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3644: a cold read larger than the reader's ceiling runs in batches
//! instead of being refused. The query gets slower, not refused.
//!
//! A search statement is a chain of stages: `WITH stage_0 AS (SELECT
//! <projection> FROM <source> WHERE <time> AND (<search>)), stage_1 AS (…)
//! … SELECT … FROM stage_N`. `stage_0` is row-wise (a filter and a
//! projection of each source row), so it distributes over any split of the
//! source: the `stage_0` rows of the whole window are exactly the union of
//! the `stage_0` rows of its parts. Every later stage (stats of any kind,
//! `dc`, `avg`, percentiles, `sort | head`, `rare`, `top`, `eval`, `where`,
//! timecharts) then runs once over that union, so the batched answer is the
//! unbatched one for every statement shape, with no per-aggregate merge.
//!
//! A batched read therefore:
//! 1. groups the window's parts into batches whose data files (signed sizes,
//!    whole-file upper bounds) fit half the cold ceiling;
//! 2. per batch, leases its files (one selection), spools that batch's
//!    `stage_0` rows to a zstd Native file on the job lane (Native keeps
//!    every ClickHouse type exactly), and releases the lease, so its objects
//!    are evictable before the next batch is leased;
//! 3. runs the statement once with `stage_0` read from the spool files.
//!
//! The lease of one batch and the spool together stay within the ceiling
//! (each at most half), which is the cache share the ceiling grants one
//! heavy read. Progress events are the same: each batch's lease reports its
//! cold bytes, and the whole estimate is announced up front.
//!
//! Shapes that cannot be batched keep the refusal (`batchable` says why):
//! a statement without a row-wise `stage_0` (a raw-event page reads newest
//! first in chunks instead, see `progressive`), a `stage_0` bounded by
//! `ORDER BY … LIMIT` (the asset / tree / cloud / baseline re-query samples),
//! a statement reading the source more than once, a single part over the
//! ceiling, and a filter whose matching rows alone exceed the spool share.

use std::collections::{BTreeSet, VecDeque};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use serde_json::{json, Value};

use super::engine::{
    decode_rows, internal, map_fetch_error, plan_logs, PartQueryEngine,
    PartQueryError, QueryResult, Run, Selection,
};
use super::membership::Membership;
use crate::parts::format::PartId;
use crate::planner::{CompiledQuery, NativeQueryPlan};

const SPILL_PARAM: &str = "nano_cold_spill";
const SPILL_GLOB_PARAM: &str = "nano_cold_spill_glob";
const SPILL_STRUCTURE_PARAM: &str = "nano_cold_spill_structure";
const SPILL_SUFFIX: &str = ".native.zst";

/// See [`PartQueryEngine::spooled_columns`].
struct Spooled {
    select: String,
    structure: String,
}
/// More batches than any window could need at a sane ceiling; a guard
/// against a planning defect, not a product limit.
const MAX_BATCHES: usize = 4_096;

/// `sql` with the content of every quoted literal and identifier blanked
/// (same byte offsets), so keywords and parentheses inside strings are not
/// mistaken for structure.
fn mask_quoted(sql: &str) -> Vec<u8> {
    let mut masked = sql.as_bytes().to_vec();
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for byte in masked.iter_mut() {
        match quote {
            None => {
                if matches!(*byte, b'\'' | b'"' | b'`') {
                    quote = Some(*byte);
                }
            }
            Some(open) => {
                if escaped {
                    escaped = false;
                    *byte = b' ';
                } else if *byte == b'\\' {
                    escaped = true;
                    *byte = b' ';
                } else if *byte == open {
                    quote = None;
                } else {
                    *byte = b' ';
                }
            }
        }
    }
    masked
}

/// Byte range of `stage_0`'s body (inside its parentheses) when `sql` opens
/// with `WITH stage_0 AS (`.
fn stage_0_body(sql: &str) -> Option<Range<usize>> {
    static HEAD: std::sync::OnceLock<regex::bytes::Regex> = std::sync::OnceLock::new();
    let head = HEAD.get_or_init(|| regex::bytes::Regex::new(r"^\s*WITH\s+stage_0\s+AS\s*\(").expect("static regex"));
    let masked = mask_quoted(sql);
    let open = head.find(&masked)?.end() - 1;
    let mut depth = 0_usize;
    for (offset, byte) in masked[open..].iter().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + 1..open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// The text of `masked` at parenthesis depth 0 (nested content blanked).
fn top_level(masked: &[u8]) -> String {
    let mut depth = 0_usize;
    masked
        .iter()
        .map(|byte| match byte {
            b'(' => {
                depth += 1;
                ' '
            }
            b')' => {
                depth = depth.saturating_sub(1);
                ' '
            }
            _ if depth > 0 => ' ',
            byte => *byte as char,
        })
        .collect()
}

/// A `stage_0` body that maps each source row to at most one output row on
/// its own: no ordering, bound, grouping, window, set operation or join at
/// its top level.
fn row_wise(body: &[u8]) -> bool {
    static NOT_ROW_WISE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pattern = NOT_ROW_WISE.get_or_init(|| {
        regex::Regex::new(r"(?i)\b(ORDER\s+BY|GROUP\s+BY|LIMIT|HAVING|UNION|INTERSECT|EXCEPT|WINDOW|OVER|DISTINCT|JOIN|QUALIFY)\b")
            .expect("static regex")
    });
    !pattern.is_match(&top_level(body))
}

/// Why a compiled statement cannot run in batches, or `None` when it can.
pub(super) fn not_batchable(compiled: &CompiledQuery) -> Option<&'static str> {
    if compiled.dataset != "logs" {
        return Some("only log searches read parts in batches");
    }
    if compiled.newest_first_event_rows {
        return Some("a newest-first event page reads in time chunks instead");
    }
    let Some(body) = stage_0_body(&compiled.sql) else {
        return Some("the statement has no row-wise first stage");
    };
    let placeholder = compiled.source_placeholder.as_str();
    if placeholder.is_empty() || compiled.sql.matches(placeholder).count() != 1 || !compiled.sql[body.clone()].contains(placeholder) {
        return Some("the statement reads its source more than once");
    }
    if !row_wise(&mask_quoted(&compiled.sql)[body]) {
        return Some("its first stage is bounded or aggregated (ORDER BY / LIMIT / GROUP BY)");
    }
    None
}

/// `stage_0` of a planned statement, or `None` if planning bounded the
/// source itself (a top-K page bound), which would not distribute.
fn planned_stage_0(sql: &str) -> Option<Range<usize>> {
    let body = stage_0_body(sql)?;
    let masked = mask_quoted(sql);
    let text = String::from_utf8_lossy(&masked[body.clone()]).to_ascii_uppercase();
    (!text.contains("ORDER BY")).then_some(body)
}

/// The `stage_0` columns that the statement after it (`rest`) can read, as a
/// select list; `None` keeps them all (a later `SELECT *` passes every one
/// through). `stage_0` also projects pass-through columns (`message`,
/// `raw_data`) that chDB prunes when it plans the whole statement but would
/// spool if asked for `*`, so only referenced names are kept: quoted
/// (`"name"`, `` `name` ``) or bare at a word boundary. A statement that reads
/// no column (`count()`) still spools one, so each spooled row is kept.
#[cfg(test)]
fn referenced_columns(names: &[String], rest: &str) -> Option<String> {
    referenced(names, rest).map(|kept| quoted_list(&kept))
}

fn quoted(name: &str) -> String {
    format!("`{}`", name.replace('\\', "\\\\").replace('`', "\\`"))
}

fn quoted_list(names: &[&String]) -> String {
    names.iter().map(|name| quoted(name)).collect::<Vec<_>>().join(", ")
}

fn referenced<'a>(names: &'a [String], rest: &str) -> Option<Vec<&'a String>> {
    static STAR: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let star = STAR.get_or_init(|| regex::Regex::new(r"(?i)((\bSELECT\s+(DISTINCT\s+)?|,\s*)\*[^()]*?\bFROM\s+stage_0\b|\bstage_0\.\*|\*\s*(EXCEPT|REPLACE|APPLY)\b)").expect("static regex"));
    let masked = String::from_utf8(mask_quoted(rest)).ok()?;
    if star.is_match(&masked) {
        return None;
    }
    let bare = |name: &str| {
        regex::Regex::new(&format!(r"(^|[^A-Za-z0-9_.]){}($|[^A-Za-z0-9_])", regex::escape(name))).is_ok_and(|word| word.is_match(&masked))
    };
    let mut kept = names
        .iter()
        .filter(|name| rest.contains(&format!("\"{name}\"")) || rest.contains(&format!("`{name}`")) || bare(name))
        .collect::<Vec<_>>();
    if kept.is_empty() {
        kept.extend(names.first());
    }
    if kept.is_empty() || kept.len() == names.len() {
        return None;
    }
    Some(kept)
}

fn settings_suffix(sql: &str) -> String {
    crate::executor::statement_settings(sql).map(|settings| format!(" SETTINGS {settings}")).unwrap_or_default()
}

/// Group `(part, bytes)` into batches of at most `target` bytes, in order.
/// A part larger than `target` is a batch of its own.
pub(super) fn plan_batches(estimates: &[(PartId, u64)], target: u64) -> Vec<Vec<PartId>> {
    let mut batches = Vec::new();
    let (mut batch, mut bytes) = (Vec::new(), 0_u64);
    for (part, size) in estimates {
        if !batch.is_empty() && bytes.saturating_add(*size) > target {
            batches.push(std::mem::take(&mut batch));
            bytes = 0;
        }
        batch.push(part.clone());
        bytes = bytes.saturating_add(*size);
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    batches
}

/// What a batched read leaves for its caller to run: the statement over the
/// spooled `stage_0` rows (or, when no batch matched a row, the last batch's
/// own statement over its still-leased files).
pub(super) struct ColdBatches {
    pub plan: NativeQueryPlan,
    pub evidence: Value,
    pub engine_seconds: f64,
    pub storage_rows: u64,
    pub storage_bytes: u64,
    _spill: tempfile::TempDir,
    /// Cache capacity held for the spool's bytes (released after the files
    /// are removed: fields drop in order).
    _reserved: Vec<crate::reader_object_cache::ScratchReservation>,
    _last: Option<Selection>,
}

/// Caller limits of one batched read.
#[derive(Default)]
pub(super) struct BatchFence<'a> {
    /// A durable job's per-statement scan budget.
    pub scan_budget: Option<u64>,
    /// A durable job's cancel flag, checked between batches.
    pub cancelled: Option<&'a AtomicBool>,
}

impl PartQueryEngine {
    /// NAN-3644: run `compiled`'s first stage over `[from_us, to_us]` in
    /// batches that each fit the cold ceiling (see the module docs).
    /// `planned_bytes` is the refused read's size, announced as progress.
    pub(super) async fn cold_batches(
        &self,
        compiled: &CompiledQuery,
        (from_us, to_us): (i64, i64),
        membership: Option<&Membership>,
        planned_bytes: u64,
        fence: BatchFence<'_>,
    ) -> QueryResult<ColdBatches> {
        let started = Instant::now();
        let cache = self.fetcher().cache();
        let ceiling = cache.cold_ceiling();
        // One batch's lease and the spool each take at most half the
        // ceiling, so together they stay within one heavy read's share.
        let share = (ceiling / 2).max(1);
        crate::query_timing::plan_cold_bytes(planned_bytes);
        let (parts, _, _, _) = self.snapshot(from_us, to_us).await?;
        let records = self.fetcher().records(&parts).await.map_err(map_fetch_error)?;
        let estimates = parts
            .iter()
            .zip(&records)
            .map(|(part, record)| {
                let bytes = record
                    .files
                    .data
                    .iter()
                    .filter(|data| data.min_time_us <= to_us && data.max_time_us >= from_us)
                    .filter(|data| super::prune::file_family_may_match(data.log_sources.as_deref(), data.class_id, &compiled.candidate_hints))
                    .map(|data| data.bytes)
                    .fold(0_u64, u64::saturating_add);
                (part.part_id.clone(), bytes)
            })
            .filter(|(_, bytes)| *bytes > 0)
            .collect::<Vec<_>>();
        let mut pending: VecDeque<Vec<PartId>> = plan_batches(&estimates, share).into();
        tracing::info!(batches = pending.len(), parts = estimates.len(), planned_bytes, ceiling_bytes = ceiling,
            "cold read over the ceiling; running it in batches");
        // The spool lives on the cache volume (never the container's /tmp)
        // and holds cache capacity for its bytes until the request ends.
        let spill_parent = cache.scratch_dir(crate::reader_object_cache::COLD_BATCH_SCRATCH);
        std::fs::create_dir_all(&spill_parent).map_err(internal)?;
        let spill = tempfile::Builder::new().prefix("request-").tempdir_in(&spill_parent).map_err(internal)?;
        let mut reserved = Vec::new();
        let spill_root = spill.path().to_str().ok_or_else(|| internal("spool path is not UTF-8"))?.to_string();
        let mut last: Option<(Selection, NativeQueryPlan)> = None;
        // The spooled select list, decided on the first batch (every batch
        // plans the same `stage_0`: one read schema, one compiled query).
        let mut columns: Option<Spooled> = None;
        let (mut batches, mut splits, mut spill_bytes) = (0_usize, 0_usize, 0_u64);
        let (mut engine_seconds, mut storage_rows, mut storage_bytes) = (0.0_f64, 0_u64, 0_u64);
        while let Some(batch) = pending.pop_front() {
            if fence.cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                return Err(PartQueryError::Unavailable("batched cold read was cancelled".to_string()));
            }
            if batches + splits >= MAX_BATCHES {
                return Err(PartQueryError::Budget("batched cold read exceeded its batch count".to_string()));
            }
            let is_last = pending.is_empty();
            let ids = batch.iter().cloned().collect::<BTreeSet<_>>();
            let selection = match self.select_parts(from_us, to_us, &compiled.candidate_hints, membership, &ids).await {
                Ok(selection) => selection,
                // The whole-file estimate was low (sidecars, a part's files
                // under one lease): halve the batch.
                Err(PartQueryError::ColdScanTooLarge { .. }) if batch.len() > 1 => {
                    let (older, newer) = batch.split_at(batch.len() / 2);
                    pending.push_front(newer.to_vec());
                    pending.push_front(older.to_vec());
                    splits += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            batches += 1;
            let scalar = self.scalar_plan(&selection, compiled).await?;
            let plan = crate::enrichment_read::plan_with_scalar_plan(scalar, || plan_logs(&selection, compiled, None))?;
            if let Some(budget) = fence.scan_budget.filter(|budget| plan.budget.estimated_scan_bytes > *budget) {
                return Err(PartQueryError::Budget(format!(
                    "batch scan of {} bytes exceeds its budget of {budget}", plan.budget.estimated_scan_bytes)));
            }
            let body = planned_stage_0(&plan.sql)
                .ok_or_else(|| internal("planned statement has no row-wise first stage to batch"))?;
            if columns.is_none() {
                columns = Some(self.spooled_columns(&plan, body.clone()).await?);
            }
            let path = format!("{spill_root}/batch-{batches:05}{SPILL_SUFFIX}");
            let mut spool = plan.clone();
            spool.sql = format!(
                "INSERT INTO FUNCTION file({{{SPILL_PARAM}:String}}, Native) WITH stage_0 AS ({}) SELECT {} FROM stage_0{}",
                &plan.sql[body],
                columns.as_ref().map_or("*", |spooled| spooled.select.as_str()),
                settings_suffix(&plan.sql)
            );
            spool.params.push((SPILL_PARAM.to_string(), path.clone()));
            let output = self.execute_spool(spool).await?;
            engine_seconds += output.elapsed.as_secs_f64();
            storage_rows = storage_rows.saturating_add(output.storage_rows_read);
            storage_bytes = storage_bytes.saturating_add(output.storage_bytes_read);
            match std::fs::metadata(&path) {
                Ok(meta) if meta.len() == 0 => std::fs::remove_file(&path).map_err(internal)?,
                Ok(meta) => {
                    spill_bytes = spill_bytes.saturating_add(meta.len());
                    let (cache, bytes) = (cache.clone(), meta.len());
                    match tokio::task::spawn_blocking(move || cache.reserve_scratch(bytes)).await.map_err(internal)? {
                        Ok(reservation) => reserved.push(reservation),
                        Err(error) => {
                            tracing::warn!(%error, spill_bytes, "batched cold read: the cache cannot hold the spooled rows");
                            return Err(PartQueryError::ColdScanTooLarge { needed_bytes: planned_bytes.max(spill_bytes), ceiling_bytes: ceiling, background_bytes: 0 });
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(internal(error)),
            }
            if spill_bytes > share {
                tracing::warn!(spill_bytes, share_bytes = share, "batched cold read: the matching rows outgrow the spool share");
                // The matching rows themselves are too large to stage, in
                // any lane: no background offer (background_bytes 0).
                return Err(PartQueryError::ColdScanTooLarge { needed_bytes: planned_bytes.max(spill_bytes), ceiling_bytes: ceiling, background_bytes: 0 });
            }
            // Release this batch before the next is leased; the last one
            // stays leased in case no batch matched a row (see below).
            if is_last {
                last = Some((selection, plan));
            } else {
                drop(selection);
            }
        }
        let Some((selection, last_plan)) = last else {
            return Err(PartQueryError::ColdScanTooLarge { needed_bytes: planned_bytes, ceiling_bytes: ceiling, background_bytes: cache.durable_cold_ceiling() });
        };
        let evidence = json!({
            "batches": batches, "splits": splits, "spill_bytes": spill_bytes, "planned_bytes": planned_bytes,
            "ceiling_bytes": ceiling, "batch_bytes": share, "batch_s": started.elapsed().as_secs_f64(),
        });
        if spill_bytes == 0 {
            // No batch matched a row: the last batch's own statement (its
            // `stage_0` is empty) is the answer over an empty input.
            return Ok(ColdBatches { plan: last_plan, evidence, engine_seconds, storage_rows, storage_bytes, _spill: spill, _reserved: reserved, _last: Some(selection) });
        }
        drop(selection);
        let body = planned_stage_0(&last_plan.sql).ok_or_else(|| internal("planned statement has no row-wise first stage to batch"))?;
        let mut plan = last_plan.clone();
        plan.sql = format!(
            "{}SELECT * FROM file({{{SPILL_GLOB_PARAM}:String}}, Native, {{{SPILL_STRUCTURE_PARAM}:String}}){}",
            &last_plan.sql[..body.start],
            &last_plan.sql[body.end..]
        );
        plan.params.retain(|(name, _)| plan.sql.contains(&format!("{{{name}:")));
        plan.params.push((SPILL_GLOB_PARAM.to_string(), format!("{spill_root}/batch-*{SPILL_SUFFIX}")));
        let structure = columns.map(|spooled| spooled.structure).ok_or_else(|| internal("no batch described its columns"))?;
        plan.params.push((SPILL_STRUCTURE_PARAM.to_string(), structure));
        // The final statement reads the spool, not the parts.
        plan.budget.estimated_scan_bytes = spill_bytes;
        Ok(ColdBatches { plan, evidence, engine_seconds, storage_rows, storage_bytes, _spill: spill, _reserved: reserved, _last: None })
    }

    /// What a batch spools: `stage_0`'s columns that the rest of `plan`
    /// reads, as a select list and as the spool's `file()` structure (a
    /// Native file holding no rows has no structure to infer).
    async fn spooled_columns(&self, plan: &NativeQueryPlan, body: Range<usize>) -> QueryResult<Spooled> {
        let mut describe = plan.clone();
        describe.sql = format!("DESCRIBE TABLE (WITH stage_0 AS ({}) SELECT * FROM stage_0)", &plan.sql[body.clone()]);
        // DESCRIBE reads no data and has no streamed form.
        describe.budget.estimated_scan_bytes = 0;
        let output = self.execute_materialized(describe).await?;
        let columns = decode_rows(&output.data)?
            .iter()
            .filter_map(|row| Some((row["name"].as_str()?.to_owned(), row["type"].as_str()?.to_owned())))
            .collect::<Vec<_>>();
        let names = columns.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>();
        if names.is_empty() {
            return Err(internal("first stage described no columns"));
        }
        let kept = referenced(&names, &plan.sql[body.end..]).unwrap_or_else(|| names.iter().collect());
        let structure = columns
            .iter()
            .filter(|(name, _)| kept.contains(&name))
            .map(|(name, kind)| format!("{} {kind}", quoted(name)))
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Spooled { select: quoted_list(&kept), structure })
    }

    /// NAN-3644: an interactive request's batched read (see
    /// [`Self::cold_batches`]): the final statement runs on the interactive
    /// lanes like any other.
    pub(super) async fn run_cold_batched(
        &self,
        compiled: &CompiledQuery,
        window: (i64, i64),
        membership: Option<&Membership>,
        planned_bytes: u64,
    ) -> QueryResult<Run> {
        let batched = Box::pin(self.cold_batches(compiled, window, membership, planned_bytes, BatchFence::default())).await?;
        let output = self.execute(batched.plan.clone()).await?;
        crate::query_timing::record(|p| p.funnel.cold_batches = true);
        Ok(Run {
            rows: decode_rows(&output.data)?,
            engine_seconds: batched.engine_seconds + output.elapsed.as_secs_f64(),
            storage_rows: batched.storage_rows.saturating_add(output.storage_rows_read),
            storage_bytes: batched.storage_bytes.saturating_add(output.storage_bytes_read),
            temporary_aliases: batched.plan.temporary_aliases.clone(),
            schema_defaults: batched.plan.schema_defaults.clone(),
            budget: serde_json::to_value(&batched.plan.budget).map_err(internal)?,
            planner: json!({ "cold_batches": batched.evidence }),
            continuation: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATS: &str = "WITH stage_0 AS (\n  SELECT `device.hostname`, time FROM __nano_lake_source__\n  WHERE time >= '2026-10-01' AND (lower(message) LIKE '%(x) ORDER BY%')\n),\nstage_1 AS (\n  SELECT `device.hostname`, count() AS count FROM stage_0 GROUP BY `device.hostname` ORDER BY count DESC LIMIT 10\n)\nSELECT * FROM stage_1 LIMIT 10 SETTINGS max_threads=2";

    #[test]
    fn stage_0_is_found_past_quoted_parentheses_and_keywords() {
        let body = stage_0_body(STATS).unwrap();
        let text = &STATS[body];
        assert!(text.trim_start().starts_with("SELECT `device.hostname`"), "{text}");
        assert!(text.trim_end().ends_with("ORDER BY%')"), "{text}");
        assert!(row_wise(&mask_quoted(text)), "a keyword inside a literal is not structure");
    }

    #[test]
    fn bounded_or_grouped_first_stages_are_not_row_wise() {
        for body in [
            "SELECT * FROM src WHERE x ORDER BY time DESC LIMIT 100",
            "SELECT host, count() FROM src GROUP BY host",
            "SELECT DISTINCT host FROM src",
            "SELECT row_number() OVER (ORDER BY time) FROM src",
            "SELECT * FROM src UNION ALL SELECT * FROM other",
        ] {
            assert!(!row_wise(&mask_quoted(body)), "{body}");
        }
        // Nested ordering (inside a subquery predicate) is the subquery's own.
        assert!(row_wise(&mask_quoted("SELECT * FROM src WHERE id IN (SELECT id FROM t ORDER BY id LIMIT 3)")));
    }

    #[test]
    fn planned_sources_bounded_to_a_page_are_not_batched() {
        let planned = STATS.replace("__nano_lake_source__", "(SELECT * FROM file({p:String}, Parquet) ORDER BY time DESC LIMIT 50)");
        assert!(planned_stage_0(&planned).is_none());
        let planned = STATS.replace("__nano_lake_source__", "(SELECT * FROM file({p:String}, Parquet, {s:String}))");
        assert!(planned_stage_0(&planned).is_some());
    }

    #[test]
    fn statements_without_a_first_stage_are_not_batched() {
        assert!(stage_0_body("SELECT * FROM __nano_lake_source__ WHERE x ORDER BY time DESC LIMIT 10").is_none());
        assert!(stage_0_body("WITH stage_0 AS (SELECT 1").is_none(), "unbalanced");
    }

    #[test]
    fn batches_fill_up_to_the_target_and_oversized_parts_stand_alone() {
        let part = |n: u32| PartId::parse(&format!("{n:013}-00000000000000ab")).unwrap();
        let estimates = vec![(part(1), 40), (part(2), 50), (part(3), 30), (part(4), 500), (part(5), 10)];
        let batches = plan_batches(&estimates, 100);
        assert_eq!(batches, vec![vec![part(1), part(2)], vec![part(3)], vec![part(4)], vec![part(5)]]);
        assert!(plan_batches(&[], 100).is_empty());
    }

    #[test]
    fn only_columns_the_later_stages_read_are_spooled() {
        let names = ["time", "device.hostname", "message", "raw_data", "__nano_path_0"].map(String::from);
        let rest = &STATS[stage_0_body(STATS).unwrap().end..];
        assert_eq!(referenced_columns(&names, rest).as_deref(), Some("`device.hostname`"));
        // Bare aliases and double quotes count; a literal does not hide a name.
        let rest = "), stage_1 AS (SELECT __nano_path_0, \"time\" FROM stage_0 WHERE x = 'message') SELECT * FROM stage_1";
        assert_eq!(referenced_columns(&names, rest).as_deref(), Some("`time`, `__nano_path_0`"));
        // A later `SELECT *` over stage_0 passes every column through.
        assert_eq!(referenced_columns(&names, "), stage_1 AS (SELECT * FROM stage_0 WHERE a > 1) SELECT a FROM stage_1"), None);
        assert_eq!(referenced_columns(&names, ") SELECT stage_0.* FROM stage_0"), None);
        // `count()` reads no column: one is still spooled per row.
        assert_eq!(referenced_columns(&names, "), stage_1 AS (SELECT count() AS count FROM stage_0) SELECT * FROM stage_1").as_deref(), Some("`time`"));
        // `count(*)` is not a select-star.
        assert_eq!(referenced_columns(&names, "), stage_1 AS (SELECT count(*) AS n, `message` FROM stage_0)").as_deref(), Some("`message`"));
    }

    #[test]
    fn settings_carry_over_to_the_spool_statement() {
        assert_eq!(settings_suffix(STATS), " SETTINGS max_threads=2");
        assert_eq!(settings_suffix("SELECT 1"), "");
    }
}
