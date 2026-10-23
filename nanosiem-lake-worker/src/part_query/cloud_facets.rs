// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact correlated Cloud/Asset summary acceleration. Closed request shape: every
//! extra predicate, pipeline command, cursor or table mode keeps the compiler's
//! ordinary path. Signed coverage and whole-part time containment are required.

use super::engine::{
    plan_logs, BroadNplRequest, PartQueryEngine, PartQueryError, QueryResult, Run,
};
use super::fetch::FileSet;
use crate::cloud_facet_summaries::{FIELDS, PATH};
use crate::parts::provenance::PartialKind;
use crate::planner::CompiledQuery;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

enum Shape {
    Cloud,
    Asset(Vec<(usize, BTreeSet<String>)>),
}

impl Shape {
    fn path(&self) -> &'static str {
        match self {
            Self::Cloud => PATH,
            Self::Asset(_) => crate::asset_facet_summaries::PATH,
        }
    }
    fn fields(&self) -> &'static [&'static str] {
        match self {
            Self::Cloud => &FIELDS,
            Self::Asset(_) => &crate::asset_facet_summaries::OUTPUT_FIELDS,
        }
    }
    fn project(&self, values: Vec<Value>) -> Option<Option<Vec<Value>>> {
        match self {
            Self::Cloud if values.len() == 6 => Some(Some(values)),
            Self::Asset(clauses) if values.len() == 12 => {
                // Only ASCII identity/status semantics are proved here. A noncanonical
                // endpoint could compare differently with raw vs lower(col) compilation;
                // keep the ordinary path for that whole request.
                for (index, value) in values.iter().enumerate().take(9) {
                    if let Some(text) = value.as_str() {
                        if !text.is_ascii() || (index < 7 && text != text.to_ascii_lowercase()) {
                            return None;
                        }
                    } else if !value.is_null() {
                        return None;
                    }
                }
                if values[11].as_str().is_some_and(|text| !text.is_ascii()) {
                    return None;
                }
                let matches = clauses.iter().any(|(index, allowed)| {
                    values[*index]
                        .as_str()
                        .is_some_and(|text| allowed.contains(&text.to_ascii_lowercase()))
                });
                if !matches {
                    return Some(None);
                }
                let failure = values[10].as_u64() == Some(3002)
                    && values[11]
                        .as_str()
                        .is_some_and(|status| status.eq_ignore_ascii_case("failure"));
                let user = if values[8].is_null() {
                    values[7].clone()
                } else {
                    values[8].clone()
                };
                Some(Some(vec![
                    values[9].clone(),
                    values[10].clone(),
                    json!(u8::from(failure)),
                    user,
                ]))
            }
            _ => None,
        }
    }
}

fn shape(request: &BroadNplRequest) -> Option<Shape> {
    if request.dataset != "logs"
        || request.table_view
        || request.cursor_time.is_some()
        || request.cursor_event_uid.is_some()
        || request.offset != 0
    {
        return None;
    }
    if crate::cloud_facet_summaries::reads_enabled()
        && request.limit == 50_000
        && request.query.trim()
            == format!(
                "class_uid=6003 | stats count() as event_count by {}",
                FIELDS.join(",")
            )
    {
        return Some(Shape::Cloud);
    }
    if !crate::asset_facet_summaries::reads_enabled() || request.limit != 10_000 {
        return None;
    }
    let predicate = request
        .query
        .trim()
        .strip_suffix(crate::asset_facet_summaries::SUFFIX)?;
    let nanosiem_core::query::Query::Search(expression) =
        nanosiem_core::query::parse_query(predicate).ok()?
    else {
        return None;
    };
    let mut clauses = Vec::new();
    fn collect(
        expression: &nanosiem_core::query::SearchExpr,
        clauses: &mut Vec<(usize, BTreeSet<String>)>,
    ) -> Option<()> {
        use nanosiem_core::query::{SearchExpr, Value as Literal};
        match expression {
            SearchExpr::Group(inner) => collect(inner, clauses),
            SearchExpr::Or(left, right) => {
                collect(left, clauses)?;
                collect(right, clauses)
            }
            SearchExpr::InList {
                field,
                values,
                negated: false,
            } => {
                let index = crate::asset_facet_summaries::FIELDS[..9]
                    .iter()
                    .position(|path| *path == field)?;
                let allowed = values
                    .iter()
                    .map(|value| match value {
                        Literal::String(text) if text.is_ascii() && !text.is_empty() => Some(text.to_ascii_lowercase()),
                        _ => None,
                    })
                    .collect::<Option<BTreeSet<_>>>()?;
                if clauses.len() >= 32 || allowed.len() > 1_000 {
                    return None;
                }
                clauses.push((index, allowed));
                Some(())
            }
            _ => None,
        }
    }
    collect(&expression, &mut clauses)?;
    Some(Shape::Asset(clauses))
}

fn integer(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}

pub(super) async fn run(
    engine: &PartQueryEngine,
    request: &BroadNplRequest,
    compiled: &CompiledQuery,
    from_us: i64,
    to_us: i64,
) -> QueryResult<Option<Run>> {
    let Some(shape) = shape(request) else {
        return Ok(None);
    };
    let path = shape.path();
    let started = Instant::now();
    let (parts, _, _, _) = engine.snapshot(from_us, to_us).await?;
    if parts.is_empty() {
        return Ok(None);
    }
    let local = engine
        .fetcher()
        .ensure(&parts, &[FileSet::Partial(PartialKind::EntityRanges)])
        .await
        .map_err(|error| super::engine::internal_text(format!("{error:#}")))?;
    let files = local
        .of(FileSet::Partial(PartialKind::EntityRanges))
        .collect::<Vec<_>>();
    if files.len() != parts.len() {
        return Ok(None);
    }
    let spec = super::partials::path_set(
        &files
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>(),
    )?;
    let mut params = vec![("cloud_facets".into(), spec)];
    let filter = if let Shape::Asset(clauses) = &shape {
        let mut terms = Vec::new();
        for (ordinal, (index, values)) in clauses.iter().enumerate() {
            let parameter = format!("asset_identity_{ordinal}");
            params.push((
                parameter.clone(),
                super::partials::sql_string_array(values.iter().map(String::as_str)),
            ));
            terms.push(format!(
                "has({{{parameter}:Array(String)}}, lower(JSONExtractString(value, 2, {})))",
                index + 1
            ));
        }
        // Keep the signed coverage marker, but never return every tenant
        // identity group just to discard it in Rust. Predicate values are bound.
        format!(" AND (value='' OR ({}))", terms.join(" OR "))
    } else {
        String::new()
    };
    let sql = format!(
        "SELECT _path AS file, value, events FROM file({{cloud_facets:String}}, Parquet) WHERE path='{path}'{filter} {}",
        super::partials::settings(engine)
    );
    let output = engine
        .run_sql(sql, params)
        .await
        .map_err(super::engine::map_executor_error)?;
    let mut engine_seconds = output.elapsed.as_secs_f64();
    let mut storage_rows = output.storage_rows_read;
    let mut storage_bytes = output.storage_bytes_read;
    let rows = super::engine::decode_rows(&output.data)?;
    let mut per_file: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for row in &rows {
        let Some(file) = row["file"].as_str() else {
            return Ok(None);
        };
        per_file.entry(file.to_owned()).or_default().push(row);
    }
    let mut raw = Vec::new();
    let mut covered = Vec::new();
    for part in &parts {
        let file = files
            .iter()
            .find(|file| file.part_id == part.part_id)
            .expect("selected partial");
        let answer = per_file.get(file.path.to_string_lossy().as_ref());
        let coverage = answer
            .and_then(|rows| rows.iter().find(|row| row["value"] == ""))
            .and_then(|row| integer(&row["events"]));
        if coverage == Some(part.rows) && part.min_time_us >= from_us && part.max_time_us <= to_us {
            covered.push(answer.expect("coverage exists"));
        } else {
            raw.push(part);
        }
    }
    // Mixed history stays one ordinary scan rather than a per-part fan-out.
    // Typical sliding windows need at most their two ragged boundary parts.
    if covered.is_empty() || raw.len() > 2 {
        return Ok(None);
    }
    let mut sums: BTreeMap<String, (Vec<Value>, u64)> = BTreeMap::new();
    let mut merge_bytes = 0;
    for answer in &covered {
        for row in answer.iter() {
            let Some(value) = row["value"].as_str() else {
                return Ok(None);
            };
            if value.is_empty() {
                continue;
            }
            let Ok((source, values)) = serde_json::from_str::<(String, Vec<Value>)>(value) else {
                return Ok(None);
            };
            // This mirrors the lake source visibility fence (case-insensitive).
            if request.deny_source_types.contains(&source.to_lowercase()) {
                continue;
            }
            let Some(events) = integer(&row["events"]) else {
                return Ok(None);
            };
            let Some(projected) = shape.project(values) else {
                return Ok(None);
            };
            if let Some(values) = projected {
                add(&mut sums, &mut merge_bytes, values, events, request.limit)?;
            }
        }
    }
    for part in &raw {
        let selection = engine
            .select_part(
                from_us,
                to_us,
                &compiled.candidate_hints,
                None,
                None,
                Some(&part.part_id),
            )
            .await?;
        if selection.manifest.objects.is_empty() {
            continue;
        }
        let plan = plan_logs(&selection, compiled, None)?;
        let output = engine.execute(plan).await?;
        engine_seconds += output.elapsed.as_secs_f64();
        storage_rows += output.storage_rows_read;
        storage_bytes += output.storage_bytes_read;
        let rows = super::engine::decode_rows(&output.data)?;
        if rows.len() >= compiled.limit {
            return Ok(None);
        }
        for row in rows {
            let values = shape
                .fields()
                .iter()
                .map(|field| row.get(*field).cloned().unwrap_or(Value::Null))
                .collect();
            let events = integer(&row["event_count"]).ok_or_else(|| {
                super::engine::internal_text("invalid correlated facet count".into())
            })?;
            add(&mut sums, &mut merge_bytes, values, events, request.limit)?;
        }
    }
    // NAN-3805: a stats page (NAN-3077 #5172) carries the compiler-owned
    // exact group cardinality and ordinal on every row, which the engine
    // consumes before paging. The merge holds every group (it refuses past
    // `request.limit`), so the total is exact.
    let total = sums.len();
    let rows = sums
        .into_values()
        .enumerate()
        .map(|(index, (values, events))| {
            let mut row = serde_json::Map::new();
            for (field, value) in shape.fields().iter().zip(values) {
                row.insert((*field).into(), value);
            }
            row.insert("event_count".into(), json!(events));
            if compiled.stats_page {
                row.insert("__nano_stats_total".into(), json!(total));
                row.insert("__nano_stats_ordinal".into(), json!(index + 1));
            }
            Value::Object(row)
        })
        .collect();
    let mut planner = json!({"facet_summary_parts": covered.len(), "facet_raw_parts": raw.len(), "facet_summary_wall_s": started.elapsed().as_secs_f64(), "facet_summary_path": path});
    if matches!(shape, Shape::Cloud) {
        planner["cloud_facet_summary_parts"] = json!(covered.len());
        planner["cloud_facet_raw_parts"] = json!(raw.len());
        planner["cloud_facet_summary_wall_s"] = planner["facet_summary_wall_s"].clone();
    }
    Ok(Some(Run {
        rows,
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

fn add(
    sums: &mut BTreeMap<String, (Vec<Value>, u64)>,
    merge_bytes: &mut usize,
    values: Vec<Value>,
    events: u64,
    cap: usize,
) -> QueryResult<()> {
    let key = serde_json::to_string(&values)
        .map_err(|error| super::engine::internal_text(error.to_string()))?;
    if !sums.contains_key(&key) {
        // Include parsed JSON array/value capacity as well as the owned key.
        *merge_bytes = merge_bytes.saturating_add(key.len().saturating_mul(16) + 512);
        if *merge_bytes > 64 * 1024 * 1024 {
            return Err(PartQueryError::MemoryBudget(
                "Correlated facet merge exceeds memory envelope".into(),
            ));
        }
    }
    let entry = sums.entry(key).or_insert((values, 0));
    entry.1 = entry
        .1
        .checked_add(events)
        .ok_or_else(|| PartQueryError::Unavailable("Correlated facet count overflow".into()))?;
    // Bound merge state to the product's complete-group envelope. The caller
    // can move larger summaries to a durable read; never trim before merging.
    if sums.len() > cap {
        return Err(PartQueryError::MemoryBudget(
            "Correlated facet groups exceed summary envelope".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn asset_projection_counts_overlap_once_and_retains_sql_coalesce_semantics() {
        let shape = Shape::Asset(vec![
            (0, ["host".into()].into()),
            (3, ["10.0.0.1".into()].into()),
        ]);
        let values = vec![
            json!("host"),
            Value::Null,
            Value::Null,
            json!("10.0.0.1"),
            Value::Null,
            Value::Null,
            Value::Null,
            json!("fallback"),
            json!(""),
            json!("audit"),
            json!(3002),
            json!("FaIlUrE"),
        ];
        assert_eq!(
            shape.project(values.clone()),
            Some(Some(vec![json!("audit"), json!(3002), json!(1), json!("")]))
        );
        let mut missing_user = values.clone();
        missing_user[8] = Value::Null;
        assert_eq!(shape.project(missing_user).unwrap().unwrap()[3], "fallback");
        let mut noncanonical = values.clone();
        noncanonical[0] = json!("HOST");
        assert!(shape.project(noncanonical).is_none());
        let mut unicode = values;
        unicode[8] = json!("İ");
        assert!(shape.project(unicode).is_none());
    }

    #[test]
    fn merge_keeps_array_multiplicity_and_detects_overflow() {
        let mut sums = BTreeMap::new();
        let mut bytes = 0;
        let mut values = vec![Value::Null; 6];
        values[5] = json!(["Role", "Role"]);
        add(&mut sums, &mut bytes, values.clone(), 2, 50_000).unwrap();
        add(&mut sums, &mut bytes, values.clone(), 3, 50_000).unwrap();
        assert_eq!(sums.values().next().unwrap().1, 5);
        assert!(add(&mut sums, &mut bytes, values, u64::MAX, 50_000).is_err());
    }
}
