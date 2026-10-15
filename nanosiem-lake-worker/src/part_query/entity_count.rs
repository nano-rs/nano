// SPDX-License-Identifier: AGPL-3.0-or-later
//! Closed compiled COUNT shape over leased, signed hourly entity evidence.
//! Inclusive native bounds are partitioned around a half-open indexed interior.
use super::engine::{plan_logs, BroadNplRequest, PartQueryEngine, QueryResult, Run};
use super::fetch::FileSet;
use crate::parts::{
    entity_counts::{Index, KINDS},
    provenance::PartialKind,
    HOUR_US,
};
use crate::planner::CompiledQuery;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug)]
struct Shape {
    kind: usize,
    pivot: Vec<(String, String)>,
    lowered: BTreeSet<String>,
    alias: String,
    denied: BTreeSet<String>,
}

fn shape(compiled: &CompiledQuery) -> Option<Shape> {
    if compiled.dataset != "logs" || compiled.stats_page || compiled.newest_first_event_rows {
        return None;
    }
    static SQL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let sql = SQL.get_or_init(|| regex::Regex::new(concat!(
        r#"(?s)^WITH stage_0 AS \(\s*SELECT [^\n()]* FROM __nano_lake_source__\s*"#,
        r#"WHERE time BETWEEN '([0-9: .-]+)' AND '([0-9: .-]+)'\s*AND (.*?)\s*"#,
        r#"\),\s*stage_1 AS \(\s*SELECT count\(\) AS ([A-Za-z_][A-Za-z0-9_]*)\s*FROM stage_0\s*\)\s*"#,
        r#"SELECT \* FROM stage_1 LIMIT ([0-9]+)(?: SETTINGS [^;\n]*)?\s*$"#,
    )).expect("static count shape"));
    let captures = sql.captures(&compiled.sql)?;
    let time = |text: &str| {
        chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f")
            .ok()
            .map(|t| t.and_utc().timestamp_micros())
    };
    if (time(&captures[1])?, time(&captures[2])?)
        != super::engine::compiled_window_us(compiled).ok()?
    {
        return None;
    }
    if captures[5].parse::<usize>().ok()? == 0 {
        return None;
    }
    let mut predicate = captures[3].trim();
    let mut depth = 0_i32;
    let mut expect_leg = true;
    let mut pivot = Vec::new();
    let mut lowered = BTreeSet::new();
    let mut denied = BTreeSet::new();
    let mut or_depth = i32::MAX;
    static LEG: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let leg = LEG.get_or_init(|| {
        regex::Regex::new(r#"^(lower\()?"([a-z_]+(?:\.[a-z_]+)+)"(\))? = '((?:[^'\\]|\\.)*)'"#)
            .expect("static equality")
    });
    while !predicate.is_empty() {
        if expect_leg && predicate.starts_with('(') {
            depth += 1;
            predicate = predicate[1..].trim_start();
            continue;
        }
        if !expect_leg && predicate.starts_with(')') {
            depth -= 1;
            if depth < 0 {
                return None;
            }
            predicate = predicate[1..].trim_start();
            continue;
        }
        if !expect_leg {
            if let Some(scope) = predicate.strip_prefix("AND ") {
                // Only a conjunct covering the entire OR pivot can be summed
                // by source. A gate inside an OR leg must stay native.
                if depth >= or_depth { return None; }
                let (rest, sources) = source_gate(scope)?;
                denied.extend(sources);
                predicate = rest.trim_start();
                continue;
            }
            if !denied.is_empty() { return None; }
            or_depth = or_depth.min(depth);
            predicate = predicate.strip_prefix("OR ")?.trim_start();
            expect_leg = true;
            continue;
        }
        let found = leg.captures(predicate)?;
        let lower = found.get(1).is_some();
        if lower != found.get(3).is_some() {
            return None;
        }
        let path = found[2].to_string();
        if crate::enrichment_read::sensitive(&path) {
            return None;
        }
        let raw_path = super::prune::INGEST_LOWERCASED_BLOOM_PATHS.contains(&path.as_str());
        if !lower && !raw_path {
            return None;
        }
        let mut value = String::new();
        let mut chars = found[4].chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let c = chars.next()?;
                if !matches!(c, '\\' | '\'') {
                    return None;
                }
                value.push(c);
            } else {
                value.push(c);
            }
        }
        if !value.is_ascii()
            || value.len() > crate::parts::entity_counts::MAX_VALUE_BYTES
            || value != value.to_ascii_lowercase()
        {
            return None;
        }
        if lower && raw_path {
            lowered.insert(path.clone());
        }
        pivot.push((path, value));
        if pivot.len() > 16 {
            return None;
        }
        predicate = predicate[found[0].len()..].trim_start();
        expect_leg = false;
    }
    if depth != 0 || expect_leg {
        return None;
    }
    let first_path = pivot.first()?.0.as_str();
    let kind = KINDS.iter().position(|paths| paths.contains(&first_path))?;
    if !pivot
        .iter()
        .all(|(path, value)| KINDS[kind].contains(&path.as_str()) && value == &pivot[0].1)
    {
        return None;
    }
    Some(Shape {
        kind,
        pivot,
        lowered,
        alias: captures[4].into(),
        denied,
    })
}

// Only the compiler's scalar, case-insensitive source exclusion forms.
// Unsupported syntax (including NULL/unattributed gates) stays native.
fn source_gate(text: &str) -> Option<(&str, BTreeSet<String>)> {
    let text = text.strip_prefix("lower(\"metadata.log_source\") ")?;
    let (mut rest, list) = if let Some(rest) = text.strip_prefix("!= ") {
        (rest, false)
    } else {
        (text.strip_prefix("NOT IN (")?, true)
    };
    let mut sources = BTreeSet::new();
    loop {
        rest = rest.strip_prefix('\'')?;
        let mut chars = rest.char_indices();
        let mut value = String::new();
        let end = loop {
            let (at, ch) = chars.next()?;
            match ch {
                '\'' => break at + 1,
                '\\' => {
                    let (_, escaped) = chars.next()?;
                    if !matches!(escaped, '\\' | '\'') {
                        return None;
                    }
                    value.push(escaped);
                }
                ch => value.push(ch),
            }
        };
        if value.is_empty() || !value.is_ascii() || value != value.to_ascii_lowercase() {
            return None;
        }
        sources.insert(value);
        rest = &rest[end..];
        if !list {
            break;
        }
        if let Some(next) = rest.strip_prefix(", ") {
            rest = next;
        } else {
            rest = rest.strip_prefix(')')?;
            break;
        }
    }
    Some((rest, sources))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Shape,
    Window,
    Cursor,
    DenySetPart,
    Uncovered,
    Budget,
    Evidence,
    Overflow,
}

fn reason(reason: Reason) {
    crate::query_timing::record(|p| {
        p.entity_count_fallback_reasons.insert(reason);
    });
}

// Optional evidence must leave nearly all of the interactive deadline for
// native execution. Includes discovery, footer probes, leases and decoding.
const COUNT_WRITER_FLOOR_MS: i64 = 1_791_849_600_000; // 2026-10-13 UTC
const INDEX_BUDGET: Duration = Duration::from_millis(400);
// Match the existing fetcher's bounded local path fan-out. Decodes retain
// their separate single-kind memory permit.
const LOOKUP_CONCURRENCY: usize = 8;

fn sources_allowed(
    record: &crate::parts::provenance::ProvenanceRecord,
    denied: &BTreeSet<String>,
) -> bool {
    denied.is_empty()
        || record.files.data.iter().all(|file| {
            file.log_sources.as_ref().is_some_and(|sources| {
                sources.iter().all(|source| {
                    source.is_ascii() && !denied.contains(&source.to_ascii_lowercase())
                })
            })
        })
}

/// Native uses inclusive microsecond bounds. The indexed interval excludes its end.
fn split(from: i64, to: i64) -> Option<((i64, i64), Vec<(i64, i64)>)> {
    if from > to {
        return None;
    }
    let start = from.checked_add((HOUR_US - from.rem_euclid(HOUR_US)) % HOUR_US)?;
    let exclusive_end = to.checked_add(1)?;
    let end = exclusive_end.checked_sub(exclusive_end.rem_euclid(HOUR_US))?;
    if start >= end {
        return None;
    }
    let mut native = Vec::new();
    if from < start {
        native.push((from, start - 1));
    }
    if end <= to {
        native.push((end, to));
    }
    Some(((start, end), native))
}

// Tenant-local, byte-bounded LRU of immutable value/hour cohorts. Field masks
// stay in the entry so different OR projections can share the same evidence.
const MEMO_BYTES: usize = 16 * 1024 * 1024;
struct Answers {
    entries: BTreeMap<String, (Option<Arc<Index>>, usize, u64)>,
    bytes: usize,
    clock: u64,
    cap: usize,
}
impl Default for Answers {
    fn default() -> Self {
        Self { entries: BTreeMap::new(), bytes: 0, clock: 0, cap: MEMO_BYTES }
    }
}
pub(super) struct Memo {
    answers: Mutex<Answers>,
    // Legacy whole-kind reads still require one bounded transient decode.
    decode_gate: Arc<tokio::sync::Semaphore>,
    point_gate: Arc<tokio::sync::Semaphore>,
    pub(super) coverage: Mutex<BTreeMap<String, u8>>,
    #[cfg(test)]
    decodes: std::sync::atomic::AtomicUsize,
}
impl Default for Memo {
    fn default() -> Self {
        Self {
            answers: Mutex::new(Answers::default()),
            coverage: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            decodes: Default::default(),
            decode_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            point_gate: Arc::new(tokio::sync::Semaphore::new(8)),
        }
    }
}
impl Memo {
    pub(super) fn cached(&self, key: &str) -> Option<Option<Arc<Index>>> {
        let mut memo = self.answers.lock().ok()?;
        memo.clock = memo.clock.saturating_add(1);
        let clock = memo.clock;
        let (answer, _, touched) = memo.entries.get_mut(key)?;
        *touched = clock;
        Some(answer.clone())
    }
    pub(super) fn answer(&self, key: String, answer: Option<Index>) -> Option<Arc<Index>> {
        let answer = answer.map(Arc::new);
        let cost = key.len() + 128 + answer.as_ref().map_or(0, |i| i.memo_bytes());
        let mut memo = self.answers.lock().ok()?;
        if cost > memo.cap { return answer; }
        if let Some((_, old, _)) = memo.entries.remove(&key) { memo.bytes -= old; }
        while memo.bytes + cost > memo.cap {
            let oldest = memo.entries.iter().min_by_key(|(_, (_, _, touched))| *touched)
                .map(|(key, _)| key.clone())?;
            let (_, bytes, _) = memo.entries.remove(&oldest)?;
            memo.bytes -= bytes;
        }
        memo.clock = memo.clock.saturating_add(1);
        let clock = memo.clock;
        memo.bytes += cost;
        memo.entries.insert(key, (answer.clone(), cost, clock));
        answer
    }
}

pub(super) async fn run(
    engine: &PartQueryEngine,
    request: &BroadNplRequest,
    compiled: &CompiledQuery,
) -> QueryResult<Option<Run>> {
    if request.cursor_time.is_some() || request.cursor_event_uid.is_some() {
        reason(Reason::Cursor);
        return Ok(None);
    }
    let Some(mut shape) = shape(compiled) else {
        reason(Reason::Shape);
        return Ok(None);
    };
    // Also honor normalized request denies if a future compiler changes its
    // exclusion spelling. A shape with unrecognized SQL still fails closed.
    shape.denied.extend(
        request
            .deny_source_types
            .iter()
            .map(|s| s.trim().to_ascii_lowercase()),
    );
    let (from, to) = super::engine::compiled_window_us(compiled)?;
    let Some((interior, boundaries)) = split(from, to) else {
        reason(Reason::Window);
        return Ok(None);
    };
    let started = Instant::now();
    let deadline = started + INDEX_BUDGET;
    let mut indexed = 0_u64;
    let mut covered = BTreeSet::new();
    let mut index_hours = 0_usize;
    let mut parts = Vec::new();
    let attempt = async {
        use futures::StreamExt;
        parts = engine.snapshot(from, to).await?.0;
        // Spend any cold metadata work on the freshest candidates first.
        parts.sort_by_key(|part| std::cmp::Reverse((part.max_time_us, part.part_id.clone())));
        let lookups = parts
            .iter()
            .filter(|part| part.max_time_us >= interior.0 && part.min_time_us < interior.1)
            .map(|part| {
                Box::pin(lookup(
                    engine,
                    part,
                    &shape,
                    interior,
                    deadline,
                ))
            })
            .collect::<Vec<_>>();
        let mut lookups = futures::stream::iter(lookups).buffer_unordered(LOOKUP_CONCURRENCY);
        while let Some((part, answer)) = lookups.next().await {
            if let Some(count) = answer {
                let Some(total) = indexed.checked_add(count) else {
                    reason(Reason::Overflow);
                    return Ok::<_, super::engine::PartQueryError>(false);
                };
                indexed = total;
                covered.insert(part.part_id.clone());
                let first = (interior.0 / HOUR_US).max(part.min_time_us.div_euclid(HOUR_US));
                let last = (interior.1 / HOUR_US).min(part.max_time_us.div_euclid(HOUR_US) + 1);
                index_hours += (last - first).max(0) as usize;
            }
        }
        Ok(true)
    };
    let outcome = tokio::time::timeout(INDEX_BUDGET, attempt).await;
    let index_ms = started.elapsed().as_secs_f64() * 1000.0;
    crate::query_timing::record(|p| p.entity_count_index_ms += index_ms);
    if Instant::now() >= deadline { reason(Reason::Budget); }
    match outcome {
        Err(_) => reason(Reason::Budget),
        Ok(Ok(true)) => {}
        Ok(Ok(false)) | Ok(Err(_)) => return Ok(None),
    }
    if covered.is_empty() {
        return Ok(None);
    }
    let native_started = Instant::now();
    let mut native_count = 0_u64;
    let mut engine_seconds = 0.0;
    let mut storage_rows = 0;
    let mut storage_bytes = 0;
    let mut native_parts = BTreeSet::new();
    let mut native_hours = 0_usize;
    let mut duplicate_part_hours = 0_usize;
    let uncovered = parts
        .iter()
        .filter(|p| !covered.contains(&p.part_id))
        .map(|p| p.part_id.clone())
        .collect::<BTreeSet<_>>();
    let all = parts
        .iter()
        .map(|p| p.part_id.clone())
        .collect::<BTreeSet<_>>();
    let mut legs = vec![(interior.0, interior.1 - 1, uncovered)];
    legs.extend(boundaries.into_iter().map(|(a, b)| (a, b, all.clone())));
    for (a, b, ids) in legs {
        if ids.is_empty() {
            continue;
        }
        let selection = match engine
            .select_parts(a, b, &compiled.candidate_hints, None, &ids)
            .await
        {
            // The ordinary path owns cold-budget batching. Do not turn an
            // optional index optimization into a new cold-scan rejection.
            Err(super::engine::PartQueryError::ColdScanTooLarge { .. }) => return Ok(None),
            other => other?,
        };
        if selection.manifest.objects.is_empty() {
            continue;
        }
        // Covered parts may legitimately appear in partial boundary hours,
        // but must never return in the fully indexed interior.
        if a >= interior.0 && b < interior.1 {
            duplicate_part_hours += selection.parts.iter()
                .filter(|p| covered.contains(&p.part_id))
                .map(|p| {
                    let lo = a.max(p.min_time_us).div_euclid(HOUR_US);
                    let hi = b.min(p.max_time_us).div_euclid(HOUR_US);
                    (hi - lo + 1).max(0) as usize
                }).sum::<usize>();
        }
        native_parts.extend(selection.parts.iter().map(|p| p.part_id.clone()));
        for part in &selection.parts {
            let lo = a.max(part.min_time_us).div_euclid(HOUR_US);
            let hi = b.min(part.max_time_us).div_euclid(HOUR_US);
            native_hours += (hi - lo + 1).max(0) as usize;
        }
        // Keep the original compiled predicate and aggregate; only add the
        // disjoint time fence to its source WHERE. Selection alone is pruning.
        let mut leg = compiled.clone();
        leg.sql = leg.sql.replacen("WHERE time BETWEEN", &format!("WHERE time >= fromUnixTimestamp64Micro({a}) AND time <= fromUnixTimestamp64Micro({b}) AND time BETWEEN"), 1);
        let scalar = engine.scalar_plan(&selection, &leg).await?;
        let plan = crate::enrichment_read::plan_with_scalar_plan(scalar, || {
            plan_logs(&selection, &leg, None)
        })?;
        let output = engine.execute(plan).await?;
        engine_seconds += output.elapsed.as_secs_f64();
        storage_rows += output.storage_rows_read;
        storage_bytes += output.storage_bytes_read;
        let rows = super::engine::decode_rows(&output.data)?;
        let count = count(&rows, &shape.alias)
            .ok_or_else(|| super::engine::internal_text("invalid native entity count".into()))?;
        native_count = native_count
            .checked_add(count)
            .ok_or_else(|| super::engine::internal_text("entity count overflow".into()))?;
    }
    let total = indexed
        .checked_add(native_count)
        .ok_or_else(|| super::engine::internal_text("entity count overflow".into()))?;
    let native_ms = native_started.elapsed().as_secs_f64() * 1000.0;
    crate::query_timing::record(|p| {
        p.entity_count_native_ms += native_ms;
        p.funnel.counting = true;
        p.entity_count_index_parts += covered.len();
        p.entity_count_native_parts += native_parts.len();
        p.entity_count_index_hours += index_hours;
        p.entity_count_native_hours += native_hours;
    });
    // Diagnostics must never execute a second, whole-window count. Parity
    // checks belong in the native fixture, outside the interactive request.
    let planner = json!({"entity_count_index_ms":index_ms,"entity_count_native_ms":native_ms,"entity_count_index_parts":covered.len(),"entity_count_native_parts":native_parts.len(),"entity_count_index_hours":index_hours,"entity_count_native_hours":native_hours,"entity_count_duplicate_part_hours":duplicate_part_hours});
    Ok(Some(Run {
        rows: vec![json!({shape.alias:total})],
        engine_seconds,
        storage_rows,
        storage_bytes,
        temporary_aliases: BTreeSet::new(),
        schema_defaults: Vec::new(),
        budget: Value::Null,
        planner,
        continuation: None,
    }))
}
async fn lookup<'a>(
    engine: &PartQueryEngine,
    part: &'a crate::parts::part_log::PartRef,
    shape: &Shape,
    interior: (i64, i64),
    deadline: Instant,
) -> (&'a crate::parts::part_log::PartRef, Option<u64>) {
    let work = async {
        let record = engine
            .fetcher()
            .record(part)
            .await
            .map_err(|_| reason(Reason::Evidence))
            .ok()?;
        if !shape
            .lowered
            .iter()
            .all(|path| record.lowercased_at_rest.contains(path))
        {
            reason(Reason::Evidence);
            return None;
        }
        // The partial's footer hint first (no extra request); a part whose
        // partial does not cover the kind may carry a signed count record
        // from a counts-only backfill (NAN-3801).
        let partial = record
            .files
            .partials
            .iter()
            .find(|p| p.kind == PartialKind::EntityRanges);
        let mut partial_cover = 0;
        if let Some(partial) = partial {
            let coverage = engine
                .entity_count_memo
                .coverage
                .lock()
                .ok()?
                .get(&partial.sha256)
                .copied();
            partial_cover = match coverage {
                Some(answer) => answer,
                // Apply the floor to the immutable generation, never the
                // historical event window. A backfill publishes a new PartId
                // and is probed even when all its events predate the writer.
                None if part.part_id.created_unix_ms() < COUNT_WRITER_FLOOR_MS => 0,
                None => {
                    let answer = engine
                        .fetcher()
                        .entity_count_coverage_hint(part, &record)
                        .await
                        .map_err(|_| reason(Reason::Evidence))
                        .ok()?;
                    let mut memo = engine.entity_count_memo.coverage.lock().ok()?;
                    if memo.len() >= 16_384 {
                        memo.clear();
                    }
                    memo.insert(partial.sha256.clone(), answer);
                    answer
                }
            };
        }
        let (digest, might_cover, count_record) = match partial {
            Some(partial) if partial_cover & (1 << shape.kind) != 0 => (partial.sha256.clone(), partial_cover, None),
            _ => match engine.fetcher().signed_count_record(part).await {
                Ok(Some(signed)) => (signed.file.sha256.clone(), signed.coverage_mask | 128, Some(signed)),
                Ok(None) => {
                    reason(Reason::Uncovered);
                    return None;
                }
                Err(_) => {
                    reason(Reason::Evidence);
                    return None;
                }
            },
        };
        let is_v2 = might_cover & 128 != 0;
        if !is_v2 && !sources_allowed(&record, &shape.denied) {
            reason(Reason::DenySetPart);
            return None;
        }
        if might_cover & (1 << shape.kind) == 0 {
            reason(Reason::Uncovered);
            return None;
        }
        let key = format!("{}:{}:{}", digest, shape.kind, shape.pivot[0].1);
        let index = match engine.entity_count_memo.cached(&key) {
            Some(answer) => answer,
            None => {
                let kind = shape.kind;
                let value = shape.pivot[0].1.clone();
                let bounds = (part.rows, part.min_time_us, part.max_time_us);
                let gate = if is_v2 { &engine.entity_count_memo.point_gate } else { &engine.entity_count_memo.decode_gate };
                let permit = gate.clone().acquire_owned().await.ok()?;
                #[cfg(test)]
                engine.entity_count_memo.decodes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let decoded = if is_v2 {
                    let (reader, groups, lease, permit) = match &count_record {
                        Some(signed) => engine.fetcher().entity_count_record_reader(part, signed, kind, &value, permit).await.ok()?,
                        None => engine.fetcher().entity_count_point_reader(part, &record, kind, &value, permit).await.ok()??,
                    };
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let _lease = lease;
                        Index::from_reader(reader, kind, Some(value), Some(groups), bounds.0, bounds.1, bounds.2, Some(deadline))
                    }).await.ok()?.ok()?
                } else {
                    let local = engine.fetcher().ensure(std::slice::from_ref(part),
                        &[FileSet::Partial(PartialKind::EntityRanges)]).await.ok()?;
                    let path = local.of(FileSet::Partial(PartialKind::EntityRanges)).next()?.path.clone();
                    tokio::task::spawn_blocking(move || {
                        let _lease = local;
                        let _permit = permit;
                        Index::from_kind_file_before(&path, kind, bounds.0, bounds.1,
                            bounds.2, Some(deadline)).map(|index| index.map(|i| i.select_value(kind, &value)))
                    }).await.ok()?.ok()?
                };
                if Instant::now() >= deadline { reason(Reason::Budget); return None; }
                engine.entity_count_memo.answer(key, decoded)
            }
        };
        let pivot = shape.pivot.iter().map(|(p, v)| (p.as_str(), v.as_str())).collect::<Vec<_>>();
        let index = index?;
        if index.has_source_dimension() != is_v2 { reason(Reason::Evidence); return None; }
        let answer = if is_v2 { index.count_allowed(interior, &pivot, &shape.denied) }
            else { index.count_from_index(interior, &pivot) };
        if answer.is_none() {
            reason(Reason::Uncovered);
        }
        answer
    };
    let answer = work.await;
    (part, answer)
}

#[cfg(test)]
mod tests;

fn count(rows: &[Value], alias: &str) -> Option<u64> {
    if rows.len() != 1 {
        return None;
    }
    rows[0][alias]
        .as_u64()
        .or_else(|| rows[0][alias].as_str()?.parse().ok())
}

#[cfg(test)]
mod native_tests;
