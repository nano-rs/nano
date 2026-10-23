// SPDX-License-Identifier: AGPL-3.0-or-later

//! `| baseline` view builder (NAN-1868) — exposes entity baselining in general
//! search. Given a resolved entity and the search's time range (the "current"
//! window under examination), it looks back `window` days before that window and
//! reports the values the entity has NOT done in that lookback, per dimension,
//! with a coverage flag. It reuses the shadow-investigator primitives
//! (`crate::baseline`) and the entity-keyed `SearchService` methods
//! (`entity_dimension_firsts` / `entity_activity_buckets` /
//! `entity_hourly_activity_scoped`) — no reimplementation of the anti-join or the
//! coverage gating.

use super::*;
use crate::auth::ScopeSet;
use crate::baseline::{self, BaselineSpans};
use crate::search::query_processing::BaselineCommandInfo;

/// Current window (the analyst's search range) is capped so `<wide range> |
/// baseline` can't become a full scan — baseline scans this window PLUS the
/// lookback.
pub(crate) const MAX_BASELINE_CURRENT_DAYS: i64 = 7;

/// Upper bound on the `window=` lookback. The new-to-entity check scans raw logs
/// per dimension (~0.3–0.8 GiB/entity at 7d), so an unbounded window is a
/// request-level DoS vector; and values large enough to overflow
/// `chrono::Duration::days` (~1.07e8 days) panic `BaselineSpans::new`. Reject
/// anything beyond this rather than clamp, so the analyst knows the window was
/// too wide. 90d is a generous interactive ceiling (default is 7d).
const MAX_BASELINE_NEW_WINDOW_DAYS: i64 = 90;

/// Validate and normalise the requested `window=` lookback into whole days.
/// Rejects oversized windows (DoS + `chrono::Duration::days` overflow) with a
/// clear error; floors at 1 day. Pure so it is unit-testable without a DB.
fn validated_new_window_days(window: std::time::Duration) -> Result<i64, SearchError> {
    // as_secs() is u64; divide first so an astronomically large duration can't
    // wrap when narrowed to i64. The bound is checked in u64.
    let requested = window.as_secs() / 86_400;
    if requested > MAX_BASELINE_NEW_WINDOW_DAYS as u64 {
        return Err(SearchError::SqlValidationError(format!(
            "| baseline window is limited to {MAX_BASELINE_NEW_WINDOW_DAYS} days (requested \
             {requested}d) — narrow the window. The lookback scans raw logs per dimension, so \
             it is deliberately bounded."
        )));
    }
    Ok((requested.max(1)) as i64)
}

#[derive(Debug, Clone, Copy)]
struct LakeBaselineDimension {
    fields: &'static [&'static str],
    label: &'static str,
    source_side_only: bool,
}

fn lake_baseline_dimensions(entity_type: &str) -> Vec<LakeBaselineDimension> {
    match entity_type {
        "user" => vec![
            LakeBaselineDimension {
                fields: &["src_endpoint.hostname", "device.hostname"],
                label: "hosts",
                source_side_only: true,
            },
            LakeBaselineDimension {
                fields: &["src_endpoint.ip"],
                label: "source IPs",
                source_side_only: true,
            },
            LakeBaselineDimension {
                fields: &["process.name"],
                label: "processes",
                source_side_only: true,
            },
        ],
        "host" => vec![
            LakeBaselineDimension {
                fields: &["user.name", "actor.user.name"],
                label: "users",
                source_side_only: false,
            },
            LakeBaselineDimension {
                fields: &["process.name"],
                label: "processes",
                source_side_only: true,
            },
            LakeBaselineDimension {
                fields: &["dst_endpoint.ip"],
                label: "destination IPs",
                source_side_only: true,
            },
        ],
        "ip" => vec![
            LakeBaselineDimension {
                fields: &["src_endpoint.hostname", "device.hostname"],
                label: "hosts",
                source_side_only: false,
            },
            LakeBaselineDimension {
                fields: &["dst_endpoint.port"],
                label: "ports",
                source_side_only: false,
            },
            LakeBaselineDimension {
                fields: &["user.name", "actor.user.name"],
                label: "users",
                source_side_only: false,
            },
        ],
        _ => Vec::new(),
    }
}

/// Wall budget for one lean `| baseline` (NAN-3059): below the 60 s gateway
/// timeout with room for response assembly and transport.
const LAKE_BASELINE_WALL_BUDGET: std::time::Duration = std::time::Duration::from_secs(40);

/// Lake baseline reads in flight at once: the tenant query role admits two.
const LAKE_BASELINE_CONCURRENCY: usize = 2;

/// One `field=value | timechart` per source-side entity field (NAN-3059), the
/// shape the part count rollup answers without a raw scan.
fn lake_baseline_activity_queries(
    entity_type: &str,
    value: &str,
) -> Result<Vec<String>, SearchError> {
    // Validates the value exactly as the entity predicate does.
    lake_baseline_entity_predicate(entity_type, value, true)?;
    let literal = crate::query::npl_quoted_literal(value);
    let fields: &[&str] = match entity_type {
        "user" => &["user.name", "actor.user.name"],
        "host" => &["src_endpoint.hostname", "device.hostname"],
        "ip" => &["src_endpoint.ip"],
        _ => &[],
    };
    Ok(fields
        .iter()
        .map(|field| format!("{field}={literal} | timechart span=1h count"))
        .collect())
}

/// NAN-3256: rows the current-window read of one dimension may return. The
/// window is short (the analyst's range), so this bounds only pathological
/// fan-out; hitting it is the one way a dimension becomes "incomplete".
const LAKE_BASELINE_WINDOW_ROW_CAP: usize = 2_000;

/// NAN-3260: window values checked against the lookback per query. Every
/// lookback read of an entity pivot opens the same whole files whatever its
/// IN list holds, so fewer, larger batches are cheaper (was 500).
const LAKE_BASELINE_IN_BATCH_VALUES: usize = 1_000;

/// NAN-3260: nPL bytes one lookback check spends on its IN lists, summed
/// over the dimension's fields (each field repeats the list) and the
/// `startsWith` a dotless hostname expands to. Far below the lake worker's
/// 256 KiB query-text bound.
const LAKE_BASELINE_IN_QUERY_BYTES: usize = 96 * 1024;

/// NAN-3256: rows one lookback check may return (value combinations across a
/// dimension's fields). Reaching it marks the dimension incomplete.
const LAKE_BASELINE_LOOKBACK_ROW_CAP: usize = 10_000;

fn lake_baseline_present(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|field| format!("{field}!=\"\""))
        .collect::<Vec<_>>()
        .join(" OR ")
}

/// NAN-3256 phase (a): the distinct values of one dimension in the CURRENT
/// window only, its fields grouped together and folded back into per-value
/// (count, first_seen) by [`fold_lake_baseline_dimension`].
fn lake_baseline_window_query(entity_predicate: &str, fields: &[&str]) -> String {
    format!(
        "({entity_predicate}) AND ({}) | stats count,min(time) as first_seen by {} | sort -first_seen | head {LAKE_BASELINE_WINDOW_ROW_CAP}",
        lake_baseline_present(fields),
        fields.join(", "),
    )
}

/// NAN-3256 phase (b): which of `values` the entity already used in the
/// lookback. The per-field IN lists are ORed, so a value counts as seen in
/// whichever of the dimension's fields carried it.
fn lake_baseline_lookback_query(
    entity_predicate: &str,
    fields: &[&str],
    values: &[String],
) -> String {
    let list = values
        .iter()
        .map(|value| crate::query::npl_quoted_literal(value))
        .collect::<Vec<_>>()
        .join(", ");
    let any = fields
        .iter()
        .map(|field| format!("{field} IN ({list})"))
        .collect::<Vec<_>>()
        .join(" OR ");
    format!(
        "({entity_predicate}) AND ({any}) | stats min(time) as first_seen by {}",
        fields.join(", ")
    )
}

/// NAN-3256: does the dimension have ANY lookback history for the entity?
/// Asked only when none of the window values were seen before, so "every
/// value is new" can be told apart from "this dimension was never populated".
fn lake_baseline_history_query(entity_predicate: &str, fields: &[&str]) -> String {
    format!(
        "({entity_predicate}) AND ({}) | head 1",
        lake_baseline_present(fields)
    )
}

/// True when `value` survives the nPL literal round trip unchanged, so an IN
/// check over it asks about exactly this value.
fn lake_baseline_checkable(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.chars().any(char::is_control)
        && !(value.contains('"') && value.contains('\''))
}

/// What one value costs a lookback check's query text: its quoted literal
/// in every field's IN list, plus the `startsWith(field, 'v.')` a dotless
/// value expands to on a hostname field.
fn lake_baseline_value_cost(value: &str, fields: &[&str]) -> usize {
    let literal = value.len() + 4;
    let dotless = !value.contains('.');
    fields
        .iter()
        .map(|field| {
            if dotless && field.ends_with("hostname") {
                literal * 2 + 32
            } else {
                literal
            }
        })
        .sum::<usize>()
        .max(1)
}

/// Split `values` into IN-list batches bounded by count and by the query
/// text their lists cost across `fields`.
fn lake_baseline_batches(values: &[String], fields: &[&str]) -> Vec<Vec<String>> {
    let mut batches = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut bytes = 0;
    for value in values {
        let cost = lake_baseline_value_cost(value, fields);
        if !current.is_empty()
            && (current.len() >= LAKE_BASELINE_IN_BATCH_VALUES
                || bytes + cost > LAKE_BASELINE_IN_QUERY_BYTES)
        {
            batches.push(std::mem::take(&mut current));
            bytes = 0;
        }
        bytes += cost;
        current.push(value.clone());
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// Whether a window value was seen in the lookback. Matching is
/// case-insensitive like the IN filter; a dotless hostname also matches its
/// FQDN, because the hostname IN filter expands it the same way `=` does.
fn lake_baseline_seen(
    seen: &std::collections::BTreeMap<String, chrono::DateTime<chrono::Utc>>,
    fields: &[&str],
    value: &str,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let lower = value.to_lowercase();
    if let Some(first_seen) = seen.get(&lower) {
        return Some(*first_seen);
    }
    if fields.iter().any(|field| field.ends_with("hostname")) && !lower.contains('.') {
        let prefix = format!("{lower}.");
        return seen
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .map(|(_, first_seen)| *first_seen)
            .min();
    }
    None
}

/// NAN-3256: the known/new split of one dimension from its current-window
/// values and the lookback sightings of exactly those values. A window value
/// absent from the lookback is a first sighting; nothing is inferred from a
/// result cap. `truncated` is set when the window read hit its bound or
/// (NAN-3260) part of the comparison was unread for its size.
#[allow(clippy::too_many_arguments)]
fn lake_baseline_split(
    label: &'static str,
    fields: &[&str],
    window: Vec<(String, u64, chrono::DateTime<chrono::Utc>)>,
    seen: &std::collections::BTreeMap<String, chrono::DateTime<chrono::Utc>>,
    truncated: bool,
    has_history: bool,
    coverage: baseline::BaselineCoverage,
) -> baseline::DimensionBaseline {
    let mut known = Vec::new();
    let mut fresh = Vec::new();
    for (value, count, window_first_seen) in window {
        if value.trim().is_empty() || value == "-" || value.eq_ignore_ascii_case("null") {
            continue;
        }
        if !lake_baseline_checkable(&value) {
            // Never checked against the lookback, so never claimed as new.
            continue;
        }
        match lake_baseline_seen(seen, fields, &value) {
            Some(first_seen) => known.push(baseline::PeerValue {
                value,
                count,
                first_seen,
            }),
            None => fresh.push(baseline::PeerValue {
                value,
                count,
                first_seen: window_first_seen,
            }),
        }
    }
    let known_cardinality = known.len();
    known.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
    known.truncate(baseline::MAX_PEERS_SHOWN);
    // Newest first sighting first, then the busiest.
    fresh.sort_by(|a, b| {
        b.first_seen
            .cmp(&a.first_seen)
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.value.cmp(&b.value))
    });
    fresh.truncate(baseline::MAX_NEW_SHOWN);
    let blind = coverage.is_blind() || !(has_history || known_cardinality > 0);
    baseline::DimensionBaseline {
        label,
        known,
        known_cardinality,
        new_to_entity: if blind { Vec::new() } else { fresh },
        truncated,
        // Every reported value was checked against the lookback.
        baseline_unknown: false,
    }
}

fn fold_lake_baseline_dimension(
    fields: &[&str],
    rows: &[serde_json::Value],
) -> Vec<(String, u64, chrono::DateTime<chrono::Utc>)> {
    let mut values: std::collections::BTreeMap<String, (u64, chrono::DateTime<chrono::Utc>)> =
        std::collections::BTreeMap::new();
    for row in rows {
        let Some(first_seen) = row
            .get("first_seen")
            .and_then(serde_json::Value::as_str)
            .and_then(parse_baseline_lake_time)
        else {
            continue;
        };
        let count = row.get("count").and_then(baseline_count).unwrap_or(0);
        let mut seen_in_row = std::collections::BTreeSet::new();
        for field in fields {
            let Some(value) = row
                .get(*field)
                .and_then(value_as_baseline_string)
                .filter(|value| !value.trim().is_empty() && value != "-")
            else {
                continue;
            };
            // The same value in two fields of one row is one observation.
            if !seen_in_row.insert(value.clone()) {
                continue;
            }
            values
                .entry(value)
                .and_modify(|current| {
                    current.0 = current.0.saturating_add(count);
                    current.1 = current.1.min(first_seen);
                })
                .or_insert((count, first_seen));
        }
    }
    values
        .into_iter()
        .map(|(value, (count, first_seen))| (value, count, first_seen))
        .collect()
}

fn lake_baseline_entity_predicate(
    entity_type: &str,
    value: &str,
    source_side_only: bool,
) -> Result<String, SearchError> {
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
        || (value.contains('"') && value.contains('\''))
    {
        return Err(SearchError::SqlValidationError(
            "baseline entity value cannot be represented safely in nPL".to_string(),
        ));
    }
    let literal = crate::query::npl_quoted_literal(value);
    let predicate = match entity_type {
        "user" => format!("(user.name={literal} OR actor.user.name={literal})"),
        "host" => {
            let mut fields = vec!["src_endpoint.hostname", "device.hostname"];
            if !source_side_only {
                fields.push("dst_endpoint.hostname");
            }
            format!(
                "({})",
                fields
                    .into_iter()
                    .map(|field| format!("{field}={literal}"))
                    .collect::<Vec<_>>()
                    .join(" OR ")
            )
        }
        "ip" => {
            let mut fields = vec!["src_endpoint.ip"];
            if !source_side_only {
                fields.push("dst_endpoint.ip");
            }
            format!(
                "({})",
                fields
                    .into_iter()
                    .map(|field| format!("{field}={literal}"))
                    .collect::<Vec<_>>()
                    .join(" OR ")
            )
        }
        _ => {
            return Err(SearchError::SqlValidationError(format!(
                "unsupported baseline entity type {entity_type:?}"
            )));
        }
    };
    Ok(predicate)
}

fn parse_baseline_lake_time(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|value| value.and_utc())
        })
}

/// A lake count: a JSON number, or the quoted decimal ClickHouse emits for
/// a 64-bit integer when `output_format_json_quote_64bit_integers` is on.
fn baseline_count(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|count| count.trim().parse().ok()))
}

fn value_as_baseline_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

/// NAN-3078: the typed inputs of one lean `| baseline`, shared by the
/// interactive lane and the durable `BaselineV1` job so both evaluate exactly
/// the same reads.
#[derive(Debug, Clone)]
pub struct LakeBaselinePlan {
    pub entity_type: String,
    pub entity_value: String,
    pub window_days: i64,
    pub activity_days: i64,
    pub dims: Option<Vec<String>>,
    pub incident: TimeRange,
}

/// Rows of one lean baseline and whether every read finished.
#[derive(Debug, Clone)]
pub struct LakeBaselineOutcome {
    pub rows: Vec<serde_json::Value>,
    /// False when the activity history or a dimension scan did not finish
    /// before the deadline: the rows are a partial answer.
    pub complete: bool,
}

impl LakeBaselinePlan {
    pub fn new(
        info: &BaselineCommandInfo,
        entity: (String, String),
        incident: &TimeRange,
        scope_restricted: bool,
    ) -> Result<Self, SearchError> {
        let (entity_type, entity_value) = entity;
        if !baseline::is_baselineable(&entity_type) {
            return Err(SearchError::SqlValidationError(format!(
                "| baseline supports host, user, or ip entities, not {entity_type:?}"
            )));
        }
        if (incident.end - incident.start).num_days() > MAX_BASELINE_CURRENT_DAYS {
            return Err(SearchError::SqlValidationError(format!(
                "| baseline current window is limited to {MAX_BASELINE_CURRENT_DAYS} days"
            )));
        }
        // Validates the value exactly as every read's entity predicate does.
        lake_baseline_entity_predicate(&entity_type, &entity_value, true)?;
        let window_days = validated_new_window_days(info.window)?;
        let activity_days = if scope_restricted {
            window_days
        } else {
            baseline::activity_days()
        };
        let plan = Self {
            entity_type,
            entity_value,
            window_days,
            activity_days,
            dims: info.dims.clone(),
            incident: incident.clone(),
        };
        plan.validate_dims()?;
        Ok(plan)
    }

    fn validate_dims(&self) -> Result<(), SearchError> {
        let Some(requested) = self.dims.as_ref() else {
            return Ok(());
        };
        let supported = lake_baseline_dimensions(&self.entity_type)
            .iter()
            .flat_map(|dimension| dimension.fields.iter().copied())
            .collect::<std::collections::BTreeSet<_>>();
        if let Some(invalid) = requested
            .iter()
            .find(|field| !supported.contains(field.as_str()))
        {
            return Err(SearchError::SqlValidationError(format!(
                "| baseline dimension {invalid:?} is not a canonical OCSF field for {}; supported: {}",
                self.entity_type,
                supported.into_iter().collect::<Vec<_>>().join(", ")
            )));
        }
        Ok(())
    }

    pub fn spans(&self) -> BaselineSpans {
        BaselineSpans::new(
            self.incident.start,
            self.incident.end,
            self.activity_days,
            self.window_days,
        )
    }

    /// Every event any read of this baseline can touch: the lookback before
    /// the incident plus the incident itself. A durable job is admitted over
    /// exactly this range so its retention proof covers the lookback.
    pub fn contribution_range(&self) -> TimeRange {
        let spans = self.spans();
        TimeRange::new(spans.activity_start.min(spans.new_start), self.incident.end)
    }

    pub fn to_task(&self) -> crate::search::DurableLakeTask {
        crate::search::DurableLakeTask::BaselineV1 {
            entity_type: self.entity_type.clone(),
            entity_value: self.entity_value.clone(),
            window_days: self.window_days,
            activity_days: self.activity_days,
            dims: self.dims.clone(),
            incident_start_micros: self.incident.start.timestamp_micros(),
            incident_end_micros: self.incident.end.timestamp_micros(),
        }
    }

    pub fn from_task(task: &crate::search::DurableLakeTask) -> Result<Self, SearchError> {
        let crate::search::DurableLakeTask::BaselineV1 {
            entity_type,
            entity_value,
            window_days,
            activity_days,
            dims,
            incident_start_micros,
            incident_end_micros,
        } = task
        else {
            return Err(SearchError::SqlValidationError(
                "durable task is not a baseline".to_string(),
            ));
        };
        let invalid =
            || SearchError::SqlValidationError("durable baseline incident is invalid".to_string());
        let start =
            chrono::DateTime::from_timestamp_micros(*incident_start_micros).ok_or_else(invalid)?;
        let end =
            chrono::DateTime::from_timestamp_micros(*incident_end_micros).ok_or_else(invalid)?;
        task.validate()
            .map_err(|error| SearchError::SqlValidationError(error.to_string()))?;
        let plan = Self {
            entity_type: entity_type.clone(),
            entity_value: entity_value.clone(),
            window_days: *window_days,
            activity_days: *activity_days,
            dims: dims.clone(),
            incident: TimeRange::new(start, end),
        };
        lake_baseline_entity_predicate(&plan.entity_type, &plan.entity_value, true)?;
        plan.validate_dims()?;
        Ok(plan)
    }
}

/// NAN-3260: the newest lookback span read first. Most window values a
/// known entity uses were used the day before, so they leave the IN lists
/// before the older remainder is read.
const LAKE_BASELINE_FIRST_SPAN_MICROS: i64 = 86_400_000_000;

/// NAN-3260: a span refused by the cold-read budget is split down to this
/// size; a refused span this short is reported unread (incomplete).
const LAKE_BASELINE_MIN_SPAN_MICROS: i64 = 3_600_000_000;

/// NAN-3260: most pieces one refused span is split into.
const LAKE_BASELINE_MAX_PIECES: u64 = 16;

/// NAN-3260: splits one baseline may make. A lake that keeps refusing
/// (each refusal is a fast round trip, but they add up) gets the rest of
/// its refused spans reported unread instead of being split further.
const LAKE_BASELINE_MAX_SPLITS: usize = 24;

/// Inclusive microsecond bounds of a read range.
fn lake_baseline_span_micros(span: &TimeRange) -> (i64, i64) {
    (span.start.timestamp_micros(), span.end.timestamp_micros())
}

fn lake_baseline_micros_range(start: i64, end: i64) -> TimeRange {
    TimeRange::new(
        chrono::DateTime::from_timestamp_micros(start).expect("inside the source range"),
        chrono::DateTime::from_timestamp_micros(end).expect("inside the source range"),
    )
}

/// `span` cut into `pieces` contiguous, disjoint ranges, NEWEST FIRST.
/// NAN-4280: ranges are half-open `[start, end)`, so adjacent pieces share
/// their boundary and an event on it is read by exactly one piece.
fn lake_baseline_span_pieces(span: &TimeRange, pieces: u64) -> Vec<TimeRange> {
    let (start, end) = lake_baseline_span_micros(span);
    if end <= start {
        return vec![span.clone()];
    }
    let length = end - start;
    let pieces = (pieces.max(1) as i64).min(length);
    let step = (length + pieces - 1) / pieces;
    let mut out = Vec::new();
    let mut piece_start = start;
    while piece_start < end {
        let piece_end = piece_start.saturating_add(step).min(end);
        out.push(lake_baseline_micros_range(piece_start, piece_end));
        piece_start = piece_end;
    }
    out.reverse();
    out
}

/// NAN-3260: the lookback read plan, newest first: the newest day, then
/// the remainder as one span. A span the cold-read budget refuses is split
/// (see [`lake_baseline_refusal`]), so the warm case costs two reads per
/// batch and a cold 7d lookback degrades into budget-sized day pieces.
/// NAN-4280: half-open spans sharing `newest_start`.
fn lake_baseline_lookback_spans(lookback: &TimeRange) -> Vec<TimeRange> {
    let (start, end) = lake_baseline_span_micros(lookback);
    if end - start <= LAKE_BASELINE_FIRST_SPAN_MICROS {
        return vec![lookback.clone()];
    }
    let newest_start = end - LAKE_BASELINE_FIRST_SPAN_MICROS;
    vec![
        lake_baseline_micros_range(newest_start, end),
        lake_baseline_micros_range(start, newest_start),
    ]
}

/// What a baseline does with a read the lake refused for its size.
#[derive(Debug, Clone)]
enum LakeBaselineRefusal {
    /// Read these pieces of the span instead, newest first.
    Split(Vec<TimeRange>),
    /// The span is already minimal: report it unread, never a 422.
    Unread,
}

/// NAN-3260: the budget decision for one failed read. `None` when `error`
/// is not a size refusal (it propagates as before). The reader's cold-read
/// ceiling (`COLD_SCAN_TOO_LARGE`, NAN-3644; it replaced the 2 GiB
/// `COLD_BUDGET_EXCEEDED` refusal) charges every uncached file the entity
/// pivot selects over the read's whole range — a pivot leases whole files —
/// so the bytes scale with the span: split into pieces sized to ~3/4 of the
/// ceiling. A scan or memory refusal halves the span.
fn lake_baseline_refusal(error: &SearchError, span: &TimeRange) -> Option<LakeBaselineRefusal> {
    let wanted = match error {
        SearchError::ColdScanTooLarge {
            needed_bytes,
            ceiling_bytes,
            ..
        } => {
            let target = (ceiling_bytes.saturating_mul(3) / 4).max(1);
            needed_bytes.div_ceil(target).max(2)
        }
        SearchError::ResourceExhausted(kind)
            if kind.starts_with("scan") || kind.starts_with("memory") =>
        {
            2
        }
        _ => return None,
    };
    let (start, end) = lake_baseline_span_micros(span);
    let most = ((end - start + 1) / LAKE_BASELINE_MIN_SPAN_MICROS)
        .clamp(0, LAKE_BASELINE_MAX_PIECES as i64) as u64;
    if most < 2 {
        return Some(LakeBaselineRefusal::Unread);
    }
    Some(LakeBaselineRefusal::Split(lake_baseline_span_pieces(
        span,
        wanted.min(most),
    )))
}

/// Read counters of one baseline, for the `lean baseline built` line.
#[derive(Default)]
struct LakeBaselineReadStats {
    reads: std::sync::atomic::AtomicUsize,
    rows: std::sync::atomic::AtomicUsize,
    splits: std::sync::atomic::AtomicUsize,
    unread_spans: std::sync::atomic::AtomicUsize,
    /// Cold bytes the lake asked for in the reads it refused.
    refused_cold_bytes: std::sync::atomic::AtomicU64,
}

impl LakeBaselineReadStats {
    fn bump(counter: &std::sync::atomic::AtomicUsize, by: usize) {
        counter.fetch_add(by, std::sync::atomic::Ordering::Relaxed);
    }

    fn get(counter: &std::sync::atomic::AtomicUsize) -> usize {
        counter.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The decision for a failed read of `span`, counted. `None`: not a
    /// size refusal. Past [`LAKE_BASELINE_MAX_SPLITS`] a span is unread.
    fn refusal(&self, error: &SearchError, span: &TimeRange) -> Option<LakeBaselineRefusal> {
        let mut refusal = lake_baseline_refusal(error, span)?;
        if let SearchError::ColdScanTooLarge { needed_bytes, .. } = error {
            self.refused_cold_bytes
                .fetch_add(*needed_bytes, std::sync::atomic::Ordering::Relaxed);
        }
        if matches!(refusal, LakeBaselineRefusal::Split(_))
            && self
                .splits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                >= LAKE_BASELINE_MAX_SPLITS
        {
            refusal = LakeBaselineRefusal::Unread;
        }
        if matches!(refusal, LakeBaselineRefusal::Unread) {
            Self::bump(&self.unread_spans, 1);
        }
        Some(refusal)
    }
}

/// The shared pieces every baseline read goes through: the caller's
/// reader, the in-flight bound, the deadline and the counters.
struct LakeBaselineReader<'a, R> {
    read: &'a R,
    gate: tokio::sync::Semaphore,
    deadline: Option<tokio::time::Instant>,
    stats: LakeBaselineReadStats,
}

impl<R, Fut> LakeBaselineReader<'_, R>
where
    R: Fn(String, TimeRange, &'static str, usize) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<serde_json::Value>, SearchError>>,
{
    /// One read under the in-flight bound. `None`: the deadline passed (the
    /// read is cancelled; nothing starts after the deadline).
    async fn one(
        &self,
        query: String,
        range: TimeRange,
        view: &'static str,
        limit: usize,
    ) -> Option<Result<Vec<serde_json::Value>, SearchError>> {
        let run = async {
            let _permit = self.gate.acquire().await.expect("the gate is never closed");
            if self
                .deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
            {
                return None;
            }
            LakeBaselineReadStats::bump(&self.stats.reads, 1);
            let result = (self.read)(query, range, view, limit).await;
            if let Ok(rows) = &result {
                LakeBaselineReadStats::bump(&self.stats.rows, rows.len());
            }
            Some(result)
        };
        match self.deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, run).await.ok().flatten(),
            None => run.await,
        }
    }

    /// One query over `spans`, newest first, splitting a span the lake
    /// refuses for its size. `stop_on_rows` ends at the first span with a
    /// row (an existence probe).
    async fn spans(
        &self,
        query: &str,
        spans: Vec<TimeRange>,
        view: &'static str,
        limit: usize,
        stop_on_rows: bool,
    ) -> Result<LakeBaselineSpanRead, SearchError> {
        let mut out = LakeBaselineSpanRead {
            finished: true,
            ..Default::default()
        };
        let mut queue: std::collections::VecDeque<TimeRange> = spans.into();
        while let Some(span) = queue.pop_front() {
            let Some(result) = self.one(query.to_string(), span.clone(), view, limit).await else {
                out.finished = false;
                return Ok(out);
            };
            match result {
                Ok(rows) => {
                    out.truncated |= rows.len() >= limit;
                    let hit = !rows.is_empty();
                    out.rows.extend(rows);
                    if stop_on_rows && hit {
                        break;
                    }
                }
                Err(error) => {
                    let Some(refusal) = self.stats.refusal(&error, &span) else {
                        return Err(error);
                    };
                    match refusal {
                        LakeBaselineRefusal::Split(pieces) => {
                            for piece in pieces.into_iter().rev() {
                                queue.push_front(piece);
                            }
                        }
                        LakeBaselineRefusal::Unread => out.unread = true,
                    }
                }
            }
        }
        Ok(out)
    }

    /// NAN-3256 (b) + NAN-3260: which of `values` the entity used in the
    /// lookback. Spans are read newest first and a value seen in one span
    /// leaves the IN lists of the older ones; nothing is read once every
    /// value was seen. A span refused for its size is split and only the
    /// refused batches' values are re-read over its pieces.
    async fn lookback(
        &self,
        predicate: &str,
        fields: &[&str],
        values: Vec<String>,
        lookback: &TimeRange,
    ) -> Result<LakeBaselineLookback, SearchError> {
        let mut out = LakeBaselineLookback {
            finished: true,
            ..Default::default()
        };
        let mut pending = values;
        let mut queue: std::collections::VecDeque<(TimeRange, Option<Vec<String>>)> =
            lake_baseline_lookback_spans(lookback)
                .into_iter()
                .map(|span| (span, None))
                .collect();
        while let Some((span, only)) = queue.pop_front() {
            let wanted = match only {
                None => pending.clone(),
                Some(only) => only
                    .into_iter()
                    .filter(|value| pending.contains(value))
                    .collect(),
            };
            if wanted.is_empty() {
                continue;
            }
            let batches = lake_baseline_batches(&wanted, fields);
            out.reads += batches.len();
            let results = futures::future::join_all(batches.iter().map(|batch| {
                self.one(
                    lake_baseline_lookback_query(predicate, fields, batch),
                    span.clone(),
                    "baseline-lookback",
                    LAKE_BASELINE_LOOKBACK_ROW_CAP,
                )
            }))
            .await;
            let mut refused = Vec::new();
            let mut decision: Option<LakeBaselineRefusal> = None;
            for (batch, result) in batches.into_iter().zip(results) {
                let Some(result) = result else {
                    out.finished = false;
                    return Ok(out);
                };
                match result {
                    Ok(rows) => {
                        out.truncated |= rows.len() >= LAKE_BASELINE_LOOKBACK_ROW_CAP;
                        for (value, _, first_seen) in fold_lake_baseline_dimension(fields, &rows) {
                            out.seen
                                .entry(value.to_lowercase())
                                .and_modify(|current| *current = (*current).min(first_seen))
                                .or_insert(first_seen);
                        }
                    }
                    Err(error) => {
                        let Some(refusal) = self.stats.refusal(&error, &span) else {
                            return Err(error);
                        };
                        refused.extend(batch);
                        // The finest split any batch asked for.
                        decision = match (decision, refusal) {
                            (
                                Some(LakeBaselineRefusal::Split(a)),
                                LakeBaselineRefusal::Split(b),
                            ) => Some(LakeBaselineRefusal::Split(if b.len() > a.len() {
                                b
                            } else {
                                a
                            })),
                            (Some(LakeBaselineRefusal::Unread), _)
                            | (_, LakeBaselineRefusal::Unread) => Some(LakeBaselineRefusal::Unread),
                            (None, refusal) => Some(refusal),
                        };
                    }
                }
            }
            pending.retain(|value| lake_baseline_seen(&out.seen, fields, value).is_none());
            match decision {
                Some(LakeBaselineRefusal::Split(pieces)) => {
                    for piece in pieces.into_iter().rev() {
                        queue.push_front((piece, Some(refused.clone())));
                    }
                }
                Some(LakeBaselineRefusal::Unread) => out.unread = true,
                None => {}
            }
        }
        // An unread span only matters while a value is still unconfirmed.
        out.unread &= !pending.is_empty();
        Ok(out)
    }

    /// One dimension after its window read: the lookback check of its
    /// values, then (only when none was seen before) the history probe.
    async fn dimension(
        &self,
        predicate: &str,
        fields: &[&str],
        window: &[(String, u64, chrono::DateTime<chrono::Utc>)],
        lookback: &TimeRange,
    ) -> Result<LakeBaselineDimensionRun, SearchError> {
        let checkable = window
            .iter()
            .map(|(value, _, _)| value.clone())
            .filter(|value| lake_baseline_checkable(value))
            .collect::<Vec<_>>();
        let started = std::time::Instant::now();
        let check = self
            .lookback(predicate, fields, checkable, lookback)
            .await?;
        let lookback_ms = started.elapsed().as_millis() as u64;
        let mut run = LakeBaselineDimensionRun {
            has_history: Some(false),
            lookback_ms,
            probe_ms: 0,
            finished: check.finished,
            check,
        };
        if !run.finished {
            return Ok(run);
        }
        let nothing_known = !window.is_empty()
            && window
                .iter()
                .all(|(value, _, _)| lake_baseline_seen(&run.check.seen, fields, value).is_none());
        if nothing_known {
            let started = std::time::Instant::now();
            let probe = self
                .spans(
                    &lake_baseline_history_query(predicate, fields),
                    lake_baseline_lookback_spans(lookback),
                    "baseline-history",
                    1,
                    true,
                )
                .await?;
            run.probe_ms = started.elapsed().as_millis() as u64;
            run.finished = probe.finished;
            run.has_history = if !probe.rows.is_empty() {
                Some(true)
            } else if probe.unread {
                None
            } else {
                Some(false)
            };
        }
        Ok(run)
    }
}

/// Rows of one query read over spans.
#[derive(Debug, Default)]
struct LakeBaselineSpanRead {
    rows: Vec<serde_json::Value>,
    /// A span returned its row limit.
    truncated: bool,
    /// A minimal span was refused for its size and never read.
    unread: bool,
    /// False when the deadline passed first.
    finished: bool,
}

/// The lookback sightings of one dimension's window values.
#[derive(Debug, Default)]
struct LakeBaselineLookback {
    /// Lower-cased value -> earliest sighting in the spans it was read in.
    seen: std::collections::BTreeMap<String, chrono::DateTime<chrono::Utc>>,
    truncated: bool,
    unread: bool,
    finished: bool,
    reads: usize,
}

#[derive(Debug)]
struct LakeBaselineDimensionRun {
    check: LakeBaselineLookback,
    /// `None`: the probe's spans were refused for their size.
    has_history: Option<bool>,
    finished: bool,
    lookback_ms: u64,
    probe_ms: u64,
}

/// Evaluate one lean baseline through `read(query, range, view, limit)`,
/// which returns the rows of one bounded lake read. The interactive lane
/// passes its wall deadline (NAN-3059); the durable job passes none and reads
/// every dimension. At most [`LAKE_BASELINE_CONCURRENCY`] reads are in
/// flight at once, shared by every phase and dimension.
///
/// NAN-3260: a read the lake refuses for its size (cold-read budget, scan or
/// memory) is never surfaced as a refusal: its span is split and re-read,
/// and a span already at the minimum is reported as unread, which marks the
/// dimension `incomplete` instead of failing the search.
pub async fn run_lake_baseline<R, Fut>(
    plan: &LakeBaselinePlan,
    read: R,
    deadline: Option<tokio::time::Instant>,
) -> Result<LakeBaselineOutcome, SearchError>
where
    R: Fn(String, TimeRange, &'static str, usize) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<serde_json::Value>, SearchError>>,
{
    use serde_json::json;

    let started = std::time::Instant::now();
    let entity_type = plan.entity_type.as_str();
    let entity_value = plan.entity_value.as_str();
    let new_window_days = plan.window_days;
    let spans = plan.spans();
    let reader = LakeBaselineReader {
        read: &read,
        gate: tokio::sync::Semaphore::new(LAKE_BASELINE_CONCURRENCY),
        deadline,
        stats: LakeBaselineReadStats::default(),
    };
    let selected = lake_baseline_dimensions(entity_type)
        .into_iter()
        .filter(|dimension| {
            plan.dims.as_ref().is_none_or(|requested| {
                dimension
                    .fields
                    .iter()
                    .any(|field| requested.iter().any(|value| value == field))
            })
        })
        .collect::<Vec<_>>();
    let mut predicates = Vec::with_capacity(selected.len());
    for dimension in &selected {
        predicates.push(lake_baseline_entity_predicate(
            entity_type,
            entity_value,
            dimension.source_side_only,
        )?);
    }

    // NAN-3059: activity is read per source-side entity field (a plain
    // `broad_npl` read whose parts are pruned by rollup value-membership;
    // NAN-3277: an empty answer is confirmed by a raw presence read before
    // it is trusted as "no history"). Per bucket the fields
    // are merged with `max`: a lower bound on the union, so coverage is
    // never over-claimed. NAN-3260: only coverage is used here, and it
    // counts the new-to-entity window alone, so activity is read over that
    // window instead of the 30d activity span (~4x less at 7d, 30x at 1d).
    let activity_range = TimeRange::new(spans.new_start, spans.coverage_end());
    let activity_queries = lake_baseline_activity_queries(entity_type, entity_value)?;
    // NAN-3256 (a): the distinct values of each dimension in the CURRENT
    // window only. NAN-3260: read alongside activity (no phase barrier);
    // they are discarded when coverage turns out blind.
    let window_range = TimeRange::new(spans.incident_start, spans.incident_end);
    let window_queries = selected
        .iter()
        .zip(&predicates)
        .map(|(dimension, predicate)| lake_baseline_window_query(predicate, dimension.fields))
        .collect::<Vec<_>>();
    let reader = &reader;
    let activity_phase = async {
        let started = std::time::Instant::now();
        let reads = futures::future::join_all(activity_queries.iter().map(|query| {
            reader.spans(
                query,
                vec![activity_range.clone()],
                "baseline-activity",
                5_000,
                false,
            )
        }))
        .await;
        (reads, started.elapsed().as_millis() as u64)
    };
    let window_phase = async {
        let started = std::time::Instant::now();
        let reads = futures::future::join_all(window_queries.iter().map(|query| {
            reader.spans(
                query,
                vec![window_range.clone()],
                "baseline-window",
                LAKE_BASELINE_WINDOW_ROW_CAP,
                false,
            )
        }))
        .await;
        (reads, started.elapsed().as_millis() as u64)
    };
    let ((activity_reads, activity_ms), (window_reads, window_values_ms)) =
        futures::join!(activity_phase, window_phase);

    let log_built = |lookback_check_ms: u64,
                     history_probe_ms: u64,
                     values_checked: usize,
                     lookback_reads: usize,
                     dimensions: usize,
                     skipped: usize,
                     unread: usize| {
        let stats = &reader.stats;
        tracing::info!(
            entity_type,
            window_days = new_window_days,
            total_ms = started.elapsed().as_millis() as u64,
            activity_ms,
            window_values_ms,
            lookback_check_ms,
            history_probe_ms,
            values_checked,
            batches = lookback_reads,
            reads = LakeBaselineReadStats::get(&stats.reads),
            rows_read = LakeBaselineReadStats::get(&stats.rows),
            splits = LakeBaselineReadStats::get(&stats.splits),
            unread_spans = LakeBaselineReadStats::get(&stats.unread_spans),
            refused_cold_bytes = stats
                .refused_cold_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            dimensions,
            skipped,
            unread_dimensions = unread,
            complete = skipped == 0,
            "lean baseline built"
        );
    };

    let mut merged = std::collections::BTreeMap::<chrono::DateTime<chrono::Utc>, u64>::new();
    // NAN-3277: why the activity history is not a positive answer. Any entry
    // makes coverage UNKNOWN: a read that failed, was cut by the deadline or
    // was refused for its size never proves "no history".
    let mut activity_failures: Vec<String> = Vec::new();
    for result in activity_reads {
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                activity_failures.push(format!("activity read failed: {error}"));
                continue;
            }
        };
        if !result.finished {
            activity_failures.push(LAKE_BASELINE_REASON_DEADLINE.to_string());
        }
        if result.unread {
            activity_failures.push(LAKE_BASELINE_REASON_REFUSED.to_string());
        }
        let returned = result.rows.len();
        let mut parsed = 0_usize;
        for row in result.rows {
            let Some(timestamp) = row
                .get("time_bucket")
                .and_then(serde_json::Value::as_str)
                .and_then(parse_baseline_lake_time)
            else {
                continue;
            };
            let Some(count) = row.get("count").and_then(baseline_count) else {
                continue;
            };
            parsed += 1;
            let slot = merged.entry(timestamp).or_default();
            *slot = (*slot).max(count);
        }
        // NAN-3277: rows the baseline cannot read are not "zero activity".
        if returned > 0 && parsed == 0 {
            activity_failures.push(format!(
                "activity read returned {returned} rows without a readable time_bucket/count"
            ));
        }
    }
    let unknown_outcome = |failures: Vec<String>| {
        let labels = selected
            .iter()
            .map(|dimension| dimension.label.to_string())
            .collect::<Vec<_>>();
        let reason = lake_baseline_reason(&failures);
        LakeBaselineOutcome {
            rows: vec![json!({
                "entity": entity_value,
                "entity_type": entity_type,
                "dimension": serde_json::Value::Null,
                "value": serde_json::Value::Null,
                "count": 0,
                "first_seen": serde_json::Value::Null,
                // NAN-3277: never `no_history` for an entity whose history
                // was not read.
                "coverage": LAKE_BASELINE_COVERAGE_UNKNOWN,
                "partial": true,
                "incomplete": true,
                "incomplete_dimensions": labels.clone(),
                "unread_dimensions": labels,
                "reason": reason,
                "note": format!(
                    "the {entity_type}'s {new_window_days}d activity history could not be read ({reason}); baseline unknown — retry, narrow the time range or run it as a background job"
                ),
                "storage_model": "ocsf-1.9-iceberg",
            })],
            complete: false,
        }
    };
    if !activity_failures.is_empty() {
        log_built(0, 0, 0, 0, 0, selected.len(), selected.len());
        return Ok(unknown_outcome(activity_failures));
    }
    let buckets = merged.into_iter().collect::<Vec<_>>();
    let mut summary = baseline::summarize_activity(&buckets, &spans);
    // NAN-3277: the activity read answered zero. That alone never proves
    // "no history" (a rollup can answer zero for an entity it does not
    // carry): confirm with a raw existence read of the same entity fields
    // over the same lookback, newest first, before claiming it.
    let mut activity_uncounted = false;
    if summary.coverage.is_blind() {
        // NAN-4280: half-open, so the presence read ends AT the coverage end.
        let presence_end = spans.coverage_end();
        let probe = if presence_end > spans.new_start {
            reader
                .spans(
                    &lake_baseline_presence_query(entity_type, entity_value)?,
                    lake_baseline_lookback_spans(&TimeRange::new(spans.new_start, presence_end)),
                    "baseline-presence",
                    1,
                    true,
                )
                .await
        } else {
            Ok(LakeBaselineSpanRead {
                finished: true,
                ..Default::default()
            })
        };
        match probe {
            Err(error) => {
                log_built(0, 0, 0, 0, 0, selected.len(), selected.len());
                return Ok(unknown_outcome(vec![format!(
                    "activity confirmation read failed: {error}"
                )]));
            }
            Ok(probe) if !probe.rows.is_empty() => {
                // History exists but was not counted: evaluate the
                // dimensions, with coverage reported as unknown.
                tracing::warn!(
                    entity_type,
                    window_days = new_window_days,
                    "lean baseline activity read answered zero for an entity with lookback events; coverage unknown"
                );
                activity_uncounted = true;
                summary.coverage = baseline::BaselineCoverage::Thin {
                    active_days: 1,
                    total_events: 1,
                };
            }
            Ok(probe) if !probe.finished || probe.unread => {
                log_built(0, 0, 0, 0, 0, selected.len(), selected.len());
                let mut failures = Vec::new();
                if !probe.finished {
                    failures.push(LAKE_BASELINE_REASON_DEADLINE.to_string());
                }
                if probe.unread {
                    failures.push(LAKE_BASELINE_REASON_REFUSED.to_string());
                }
                return Ok(unknown_outcome(failures));
            }
            // Positively zero: the entity has no events in the lookback.
            Ok(_) => {}
        }
    }
    if summary.coverage.is_blind() {
        // NAN-3277: a confirmed "no history" is still only claimed when
        // every read of this baseline finished; a window read cut by the
        // deadline or failed makes the whole answer incomplete.
        let mut failures = Vec::new();
        for result in &window_reads {
            match result {
                Err(error) => failures.push(format!("window read failed: {error}")),
                Ok(read) if !read.finished => {
                    failures.push(LAKE_BASELINE_REASON_DEADLINE.to_string())
                }
                Ok(_) => {}
            }
        }
        if !failures.is_empty() {
            log_built(0, 0, 0, 0, 0, selected.len(), selected.len());
            return Ok(unknown_outcome(failures));
        }
    }

    let mut parsed_dimensions = Vec::new();
    let mut skipped_dimensions: Vec<String> = Vec::new();
    // Dimensions whose read hit a row bound / were partly unread for size.
    let mut capped_dimensions: Vec<String> = Vec::new();
    let mut unread_dimensions: Vec<String> = Vec::new();
    let mut lookback_check_ms = 0_u64;
    let mut history_probe_ms = 0_u64;
    let mut values_checked = 0_usize;
    let mut lookback_reads = 0_usize;
    // NAN-3277: dimensions whose reads failed, with the error.
    let mut read_errors: Vec<String> = Vec::new();
    if !summary.coverage.is_blind() {
        // NAN-3256 (b)/(c), per dimension, all dimensions at once under the
        // shared in-flight bound; see `LakeBaselineReader::lookback`.
        // NAN-4280: half-open `[new_start, incident_start)`.
        let lookback_range = TimeRange::new(spans.new_start, spans.incident_start);
        let mut windows = Vec::with_capacity(selected.len());
        for (index, result) in window_reads.into_iter().enumerate() {
            // NAN-3277: a failed window read skips its dimension (reported,
            // incomplete) instead of failing the whole baseline.
            let result = match result {
                Ok(result) => result,
                Err(error) => {
                    read_errors.push(format!("{}: {error}", selected[index].label));
                    windows.push(None);
                    continue;
                }
            };
            windows.push(result.finished.then(|| {
                (
                    fold_lake_baseline_dimension(selected[index].fields, &result.rows),
                    result.truncated,
                    result.unread,
                )
            }));
        }
        values_checked = windows
            .iter()
            .flatten()
            .map(|(values, _, _)| {
                values
                    .iter()
                    .filter(|(value, _, _)| lake_baseline_checkable(value))
                    .count()
            })
            .sum();
        let phase_started = std::time::Instant::now();
        let runs = futures::future::join_all(windows.iter().enumerate().map(|(index, window)| {
            let predicate = predicates[index].as_str();
            let fields = selected[index].fields;
            let lookback_range = &lookback_range;
            async move {
                match window {
                    Some((values, _, _)) => reader
                        .dimension(predicate, fields, values, lookback_range)
                        .await
                        .map(Some),
                    None => Ok(None),
                }
            }
        }))
        .await;
        lookback_check_ms = phase_started.elapsed().as_millis() as u64;
        for (dimension, (window, run)) in selected.iter().zip(windows.into_iter().zip(runs)) {
            let run = match run {
                Ok(run) => run,
                Err(error) => {
                    read_errors.push(format!("{}: {error}", dimension.label));
                    None
                }
            };
            let (Some((values, window_truncated, window_unread)), Some(run)) = (window, run) else {
                skipped_dimensions.push(dimension.label.to_string());
                continue;
            };
            lookback_reads += run.check.reads;
            history_probe_ms = history_probe_ms.max(run.probe_ms);
            if !run.finished {
                skipped_dimensions.push(dimension.label.to_string());
                continue;
            }
            let capped = window_truncated || run.check.truncated;
            let unread = window_unread || run.check.unread || run.has_history.is_none();
            if capped {
                capped_dimensions.push(dimension.label.to_string());
            }
            if unread {
                unread_dimensions.push(dimension.label.to_string());
            }
            tracing::debug!(
                dimension = dimension.label,
                lookback_ms = run.lookback_ms,
                probe_ms = run.probe_ms,
                reads = run.check.reads,
                "lean baseline dimension"
            );
            parsed_dimensions.push(lake_baseline_split(
                dimension.label,
                dimension.fields,
                values,
                &run.check.seen,
                capped || unread,
                run.has_history.unwrap_or(false),
                summary.coverage,
            ));
        }
    }
    log_built(
        lookback_check_ms,
        history_probe_ms,
        values_checked,
        lookback_reads,
        parsed_dimensions.len(),
        skipped_dimensions.len(),
        unread_dimensions.len(),
    );

    // NAN-3277: history exists but its activity was not counted — the
    // dimensions were compared, the coverage strength is unknown.
    let coverage = if activity_uncounted {
        LAKE_BASELINE_COVERAGE_UNKNOWN
    } else {
        summary.coverage.label()
    };
    let incomplete_dimensions = parsed_dimensions
        .iter()
        .filter(|dimension| dimension.truncated)
        .map(|dimension| dimension.label.to_string())
        .chain(skipped_dimensions.iter().cloned())
        .collect::<Vec<_>>();
    let mut incomplete_note = lake_baseline_incomplete_note(&capped_dimensions, &unread_dimensions);
    if activity_uncounted {
        let uncounted = format!(
            "the {entity_type}'s activity counts were unavailable although it has events in the last {new_window_days}d; coverage unknown"
        );
        incomplete_note = Some(match incomplete_note {
            Some(note) => format!("{uncounted}; {note}"),
            None => uncounted,
        });
    }
    let mut output = Vec::new();
    for dimension in &parsed_dimensions {
        for value in &dimension.new_to_entity {
            output.push(json!({
                "entity": entity_value,
                "entity_type": entity_type,
                "dimension": dimension.label,
                "value": value.value,
                "count": value.count,
                "first_seen": value.first_seen.to_rfc3339(),
                "coverage": coverage,
                "baseline_unknown": dimension.baseline_unknown,
                "incomplete": dimension.truncated,
                "storage_model": "ocsf-1.9-iceberg",
            }));
        }
    }
    if !skipped_dimensions.is_empty() {
        let mut reasons = Vec::new();
        if !read_errors.is_empty() {
            reasons.push(format!("read failed: {}", read_errors.join("; ")));
        }
        if skipped_dimensions.len() > read_errors.len() {
            reasons.push(LAKE_BASELINE_REASON_DEADLINE.to_string());
        }
        let note = format!(
            "partial baseline: {} not evaluated ({}); rerun with dims=… to scan them",
            skipped_dimensions.join(", "),
            reasons.join("; ")
        );
        for row in &mut output {
            row["partial"] = json!(true);
        }
        output.push(json!({
            "entity": entity_value,
            "entity_type": entity_type,
            "dimension": serde_json::Value::Null,
            "value": serde_json::Value::Null,
            "count": 0,
            "first_seen": serde_json::Value::Null,
            "coverage": coverage,
            "partial": true,
            // NAN-3277: a dimension that was never evaluated is incomplete.
            "incomplete": true,
            "incomplete_dimensions": incomplete_dimensions,
            "skipped_dimensions": skipped_dimensions,
            "unread_dimensions": skipped_dimensions,
            "reason": lake_baseline_reason(&reasons),
            "note": match &incomplete_note {
                Some(incomplete) => format!("{note}; {incomplete}"),
                None => note,
            },
            "storage_model": "ocsf-1.9-iceberg",
        }));
        return Ok(LakeBaselineOutcome {
            rows: output,
            complete: false,
        });
    }
    if output.is_empty() || incomplete_note.is_some() {
        // One summary row: "nothing new" when no value row exists, else the
        // marker that names the dimensions that are incomplete.
        let note = if !output.is_empty() {
            incomplete_note.clone().unwrap_or_default()
        } else if summary.coverage.is_blind() {
            // Reached only when the activity read AND the raw presence
            // read both completed and positively found nothing (NAN-3277).
            format!("no activity in the last {new_window_days}d; baseline unknown for this {entity_type}")
        } else {
            let nothing = format!(
                "nothing new in the last {new_window_days}d for this {entity_type} (coverage: {coverage})"
            );
            match &incomplete_note {
                Some(incomplete) => format!("{nothing}; {incomplete}"),
                None => nothing,
            }
        };
        let mut row = json!({
            "entity": entity_value,
            "entity_type": entity_type,
            "dimension": serde_json::Value::Null,
            "value": serde_json::Value::Null,
            "count": 0,
            "first_seen": serde_json::Value::Null,
            "coverage": coverage,
            "incomplete": incomplete_note.is_some(),
            "incomplete_dimensions": incomplete_dimensions,
            "note": note,
            "storage_model": "ocsf-1.9-iceberg",
        });
        if !unread_dimensions.is_empty() {
            row["unread_dimensions"] = json!(unread_dimensions);
            row["reason"] = json!(LAKE_BASELINE_REASON_REFUSED);
        }
        if activity_uncounted {
            row["reason"] = json!(LAKE_BASELINE_REASON_UNCOUNTED);
        }
        output.push(row);
    }
    Ok(LakeBaselineOutcome {
        rows: output,
        complete: true,
    })
}

/// NAN-3277: coverage of a baseline whose activity history was not read
/// to a positive answer. Never `no_history`.
const LAKE_BASELINE_COVERAGE_UNKNOWN: &str = "unknown";

/// NAN-3277: why a read did not answer.
const LAKE_BASELINE_REASON_DEADLINE: &str = "interactive wall budget reached";
const LAKE_BASELINE_REASON_REFUSED: &str =
    "part of the lookback was refused for its size (cold-read budget)";
const LAKE_BASELINE_REASON_UNCOUNTED: &str = "activity counts unavailable";

/// The distinct reasons, in first-seen order, as one string.
fn lake_baseline_reason(reasons: &[String]) -> String {
    let mut out: Vec<&str> = Vec::new();
    for reason in reasons {
        if !out.contains(&reason.as_str()) {
            out.push(reason);
        }
    }
    out.join("; ")
}

/// NAN-3277: does the entity have ANY event in a span? The same
/// source-side entity fields the activity read counts, as a raw `head 1`.
fn lake_baseline_presence_query(entity_type: &str, value: &str) -> Result<String, SearchError> {
    Ok(format!(
        "{} | head 1",
        lake_baseline_entity_predicate(entity_type, value, true)?
    ))
}

/// The caveat of the incomplete dimensions: a window that hit its row
/// bound may hide first sightings; a span the lake refused for its size
/// (NAN-3260) was not compared, so first sightings are unconfirmed.
fn lake_baseline_incomplete_note(capped: &[String], unread: &[String]) -> Option<String> {
    let mut notes = Vec::new();
    if !capped.is_empty() {
        notes.push(format!(
            "{} had more distinct values in the search window than one baseline reads; some first sightings may not be listed — narrow the time range",
            capped.join(", ")
        ));
    }
    if !unread.is_empty() {
        notes.push(format!(
            "{}: part of the lookback was too large to read inside the per-query cold-read budget; listed first sightings are unconfirmed — narrow the window or rerun",
            unread.join(", ")
        ));
    }
    (!notes.is_empty()).then(|| notes.join("; "))
}

/// Marker text of the interactive baseline's budget refusal. The search
/// handler escalates a `ResourceExhausted` to a durable `BaselineV1` job.
pub const LAKE_BASELINE_BUDGET_EXHAUSTED: &str =
    "| baseline did not finish inside the interactive wall budget";

impl SearchService {
    /// Build `| baseline` from exact OCSF 1.9 fields through the primary lake
    /// worker. The baseline window still excludes the current incident window;
    /// only the storage reader changes.
    ///
    /// NAN-3078: when the tenant has a durable job lane, a baseline that
    /// cannot finish inside the interactive deadline is refused with
    /// `ResourceExhausted` so the handler escalates it to a complete durable
    /// `BaselineV1` job. Without a durable lane the partial answer of
    /// NAN-3059 is returned, as before.
    pub(crate) async fn build_lake_baseline_view(
        &self,
        info: &BaselineCommandInfo,
        entity: (String, String),
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        // NAN-3059: the interactive gateway answers 504 at 60 s. Every lake
        // read runs against this deadline.
        let deadline = tokio::time::Instant::now() + LAKE_BASELINE_WALL_BUDGET;
        let plan = LakeBaselinePlan::new(info, entity, time_range, scope.is_restricted())?;
        let outcome = run_lake_baseline(
            &plan,
            |query, range, view, limit| async move {
                self.execute_lake_view_query(query, &range, scope, view, limit)
                    .await
                    .map(|response| response.results)
            },
            Some(deadline),
        )
        .await?;
        if !outcome.complete && self.has_durable_view_lane() {
            return Err(SearchError::ResourceExhausted(
                LAKE_BASELINE_BUDGET_EXHAUSTED.to_string(),
            ));
        }
        Ok(outcome.rows)
    }

    /// NAN-3078: queue a `| baseline` search as a complete durable
    /// `BaselineV1` job. `Ok(None)` when the query is not a baseline, so the
    /// caller continues with plain durable admission.
    ///
    /// The incident window is derived exactly as the interactive lane derives
    /// it (time modifiers, retention cutoff, newest seven days). The job is
    /// admitted over the whole contribution range (lookback + incident),
    /// bound to the retention cutoff, so its proof covers every read.
    pub(crate) async fn try_enqueue_durable_baseline(
        &self,
        request: &SearchRequest,
        user_id: uuid::Uuid,
        scope: &ScopeSet,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<Option<String>, SearchError> {
        let (cleaned, earliest, latest) = extract_time_bounds(&request.query)?;
        let Ok(parsed) = parse_query(&cleaned) else {
            return Ok(None);
        };
        let Some(info) = extract_baseline_command(&parsed) else {
            return Ok(None);
        };
        if !self.has_durable_view_lane() {
            return Err(SearchError::ServiceUnavailable(
                "durable baselines run on a lean cell job runner".to_string(),
            ));
        }
        let entity = crate::search::query_processing::resolve_baseline_entity(&parsed, &info)
            .ok_or_else(|| {
                SearchError::SqlValidationError(
                    "| baseline could not determine an entity; use host=, user=, or ip=, or lead with an exact canonical OCSF entity filter"
                        .to_string(),
                )
            })?;
        let now = chrono::Utc::now();
        let mut incident = TimeRange::new(request.time_range.start, request.time_range.end);
        if let Some(offset) = earliest {
            incident.start = offset;
        }
        if let Some(offset) = latest {
            incident.end = offset;
        }
        let incident = self
            .retention_bound_input_range(&TimeRangeInput::new(incident.start, incident.end), now)?
            .ok_or_else(|| {
                SearchError::SqlValidationError(
                    "| baseline: the search window is entirely past the tenant's retention"
                        .to_string(),
                )
            })?;
        let start = incident
            .start
            .max(incident.end - chrono::Duration::days(MAX_BASELINE_CURRENT_DAYS));
        let plan = LakeBaselinePlan::new(
            &info,
            entity,
            &TimeRange::new(start, incident.end),
            scope.is_restricted(),
        )?;
        let (generation_pin, range) = self
            .durable_view_admission("durable baselines", &plan.contribution_range())
            .await?;
        let durable_request = SearchRequest {
            query: request.query.clone(),
            time_range: TimeRangeInput::new(range.start, range.end),
            limit: Some(1),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            // NAN-3272: a durable baseline is background work like every other
            // durable product view; never inherit the escalating request's
            // interactive class.
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        let job_id = self
            .job_control()
            .create_durable_queued(
                durable_request,
                &plan.to_task(),
                user_id,
                crate::search::QueryPriority::Analytics,
                scope,
                &generation_pin,
                authority,
            )
            .await
            .map_err(|error| {
                SearchError::ServiceUnavailable(format!(
                    "durable baseline admission failed: {error}"
                ))
            })?;
        tracing::info!(
            job_id = %job_id,
            entity_type = %plan.entity_type,
            "created durable baseline job"
        );
        Ok(Some(job_id))
    }

    /// Build the `| baseline` result rows for one resolved entity.
    pub(crate) async fn build_baseline_view(
        &self,
        info: &BaselineCommandInfo,
        entity: (String, String),
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        use serde_json::json;

        let (entity_type, entity_value) = entity;

        if !baseline::is_baselineable(&entity_type) {
            return Err(SearchError::SqlValidationError(format!(
                "| baseline supports host / user / ip entities, not '{entity_type}'. Give one with \
                 host=/user=/ip=\"…\" or a src_host / src_ip / user filter."
            )));
        }

        // Bound the scan. Backstop only (NAN-2022): core_search clamps the current window
        // end-anchored upstream before calling this, so a wide range never reaches here in
        // practice. Kept as defense-in-depth for any future direct caller.
        if (time_range.end - time_range.start).num_days() > MAX_BASELINE_CURRENT_DAYS {
            return Err(SearchError::SqlValidationError(format!(
                "| baseline current window is limited to {MAX_BASELINE_CURRENT_DAYS} days — narrow \
                 your time range. Baseline scans this window PLUS the lookback used for the \
                 new-value comparison."
            )));
        }

        let new_window_days = validated_new_window_days(info.window)?;
        let scope_restricted = scope.is_restricted();
        // The agg (`entity_time_range_agg`) has no source_type column, so it cannot
        // be scoped — a restricted search draws coverage from a SCOPED raw hourly
        // scan instead, kept to the short window. Unrestricted uses the cheap agg.
        let activity_days = if scope_restricted {
            new_window_days
        } else {
            baseline::activity_days()
        };
        let spans = BaselineSpans::new(
            time_range.start,
            time_range.end,
            activity_days,
            new_window_days,
        );

        // Coverage from the entity's activity buckets.
        let buckets: Vec<(chrono::DateTime<chrono::Utc>, u64)> = if scope_restricted {
            self.entity_hourly_activity_scoped(
                scope,
                &entity_type,
                &entity_value,
                spans.activity_start,
                spans.coverage_end(),
            )
            .await?
        } else {
            self.entity_activity_buckets(
                &entity_type,
                &entity_value,
                spans.activity_start,
                spans.coverage_end(),
            )
            .await?
        }
        .into_iter()
        .map(|b| (b.hour_start, b.event_count))
        .collect();
        let summary = baseline::summarize_activity(&buckets, &spans);

        // Which dimensions the analyst asked for (None = all for the type).
        let wants = |field: &str| -> bool {
            info.dims
                .as_ref()
                .is_none_or(|d| d.iter().any(|w| w == field))
        };

        // New-to-entity — one consolidated scoped scan per filter group.
        let mut dimensions = Vec::new();
        if !summary.coverage.is_blind() {
            let mut firsts = Vec::new();
            for (source_side_only, dims) in
                baseline::dimension_scope_groups(&entity_type, true, true, true)
            {
                let fields: Vec<&str> = dims.iter().map(|d| d.field).filter(|f| wants(f)).collect();
                if fields.is_empty() {
                    continue;
                }
                let rows = self
                    .entity_dimension_firsts(
                        scope,
                        &entity_type,
                        &entity_value,
                        source_side_only,
                        &fields,
                        spans.new_start,
                        spans.incident_end,
                        baseline::NEW_TO_ENTITY_ROW_CAP,
                    )
                    .await?;
                firsts.extend(rows);
            }
            for dim in baseline::dimensions_for(&entity_type, true, true, true) {
                if !wants(dim.field) {
                    continue;
                }
                let dim_rows: Vec<(String, u64, chrono::DateTime<chrono::Utc>)> = firsts
                    .iter()
                    .filter(|f| f.dimension == dim.field)
                    .map(|f| (f.value.clone(), f.count, f.first_seen))
                    .collect();
                dimensions.push(baseline::parse_dimension_firsts(
                    dim.label,
                    dim_rows,
                    baseline::NEW_TO_ENTITY_ROW_CAP,
                    spans.incident_start,
                    summary.coverage,
                ));
            }
        }

        // Emit one row per new value; carry the coverage flag on every row.
        let coverage_label = summary.coverage.label();
        let mut out: Vec<serde_json::Value> = Vec::new();
        for d in &dimensions {
            // NAN-3256: newest first sighting first, then the busiest.
            let mut fresh = d.new_to_entity.iter().collect::<Vec<_>>();
            fresh.sort_by(|a, b| {
                b.first_seen
                    .cmp(&a.first_seen)
                    .then_with(|| b.count.cmp(&a.count))
                    .then_with(|| a.value.cmp(&b.value))
            });
            for p in fresh {
                out.push(json!({
                    "entity": entity_value,
                    "entity_type": entity_type,
                    "dimension": d.label,
                    "value": p.value,
                    "count": p.count,
                    "first_seen": p.first_seen.to_rfc3339(),
                    "coverage": coverage_label,
                    // True when the whole result cap was new values, so the
                    // baseline could not be established (a scan) — not a confirmed
                    // "never seen before".
                    "baseline_unknown": d.baseline_unknown,
                }));
            }
        }

        // Always give the analyst feedback — a summary row with the coverage even
        // when nothing was new, so "no rows" is never ambiguous.
        if out.is_empty() {
            let note = if summary.coverage.is_blind() {
                format!(
                    "no activity in the last {new_window_days}d — baseline UNKNOWN, cannot judge \
                     what is new for this {entity_type}"
                )
            } else {
                format!(
                    "nothing new in the last {new_window_days}d for this {entity_type} \
                     (coverage: {coverage_label})"
                )
            };
            out.push(json!({
                "entity": entity_value,
                "entity_type": entity_type,
                "dimension": serde_json::Value::Null,
                "value": serde_json::Value::Null,
                "count": 0,
                "first_seen": serde_json::Value::Null,
                "coverage": coverage_label,
                "note": note,
            }));
        }

        Ok(out)
    }
}

#[cfg(test)]
#[path = "baseline_nan3078_tests.rs"]
mod nan3078_tests;

#[cfg(test)]
#[path = "baseline_nan3256_tests.rs"]
mod nan3256_tests;

#[cfg(test)]
#[path = "baseline_nan3260_tests.rs"]
mod nan3260_tests;

#[cfg(test)]
#[path = "baseline_nan3277_tests.rs"]
mod nan3277_tests;

#[cfg(test)]
mod parse_tests {
    use crate::query::{parse_query, Command, PrettyPrint, Query};

    fn baseline_of(q: &str) -> Command {
        // Walk to the trailing `| baseline` command.
        fn last(query: &Query) -> Option<Command> {
            match query {
                Query::Search(_) => None,
                Query::Piped { command, .. } => Some(command.clone()),
            }
        }
        last(&parse_query(q).expect("parses")).expect("has trailing command")
    }

    #[test]
    fn infers_entity_form_parses_to_baseline() {
        let cmd = baseline_of("src_host=\"ws-1\" | baseline");
        assert!(matches!(
            cmd,
            Command::Baseline {
                entity_type: None,
                entity_value: None,
                ..
            }
        ));
    }

    #[test]
    fn explicit_host_and_window_and_dims_parse() {
        let cmd = baseline_of("* | baseline host=\"ws-1\" window=14d dims=process_name,dest_ip");
        match cmd {
            Command::Baseline {
                entity_type,
                entity_value,
                window,
                dims,
            } => {
                assert_eq!(entity_type.as_deref(), Some("host"));
                assert_eq!(entity_value.as_deref(), Some("ws-1"));
                assert_eq!(window, std::time::Duration::from_secs(14 * 86400));
                assert_eq!(
                    dims,
                    Some(vec!["process_name".to_string(), "dest_ip".to_string()])
                );
            }
            other => panic!("expected Baseline, got {other:?}"),
        }
    }

    #[test]
    fn user_and_ip_shorthands_parse() {
        assert!(matches!(
            baseline_of("* | baseline user=\"bob\""),
            Command::Baseline { entity_type, .. } if entity_type.as_deref() == Some("user")
        ));
        assert!(matches!(
            baseline_of("* | baseline ip=\"10.0.0.1\""),
            Command::Baseline { entity_type, .. } if entity_type.as_deref() == Some("ip")
        ));
    }

    #[test]
    fn default_window_is_seven_days() {
        if let Command::Baseline { window, .. } = baseline_of("* | baseline host=\"ws-1\"") {
            assert_eq!(window, std::time::Duration::from_secs(7 * 86400));
        } else {
            panic!("expected Baseline");
        }
    }

    #[test]
    fn round_trips_through_pretty_print() {
        // Detection enrichment re-parses pretty-printed queries; the command must
        // survive the round-trip.
        let original = "* | baseline host=\"ws-1\" window=14d dims=process_name";
        let parsed = parse_query(original).unwrap();
        let printed = parsed.pretty_print();
        let reparsed = parse_query(&printed).expect("pretty-printed form re-parses");
        assert_eq!(parsed, reparsed, "round-trip changed the AST: {printed}");
    }

    /// NAN-1868 (codex second-pass): an oversized `window=` must be rejected, not
    /// panic `chrono::Duration::days` or launch an unbounded raw scan.
    #[test]
    fn window_days_validation_bounds_and_floors() {
        use super::{validated_new_window_days, MAX_BASELINE_NEW_WINDOW_DAYS};
        use std::time::Duration;
        let days = |d: u64| Duration::from_secs(d * 86_400);

        assert_eq!(validated_new_window_days(days(7)).unwrap(), 7);
        // Sub-day floors to 1.
        assert_eq!(
            validated_new_window_days(Duration::from_secs(3600)).unwrap(),
            1
        );
        // The ceiling itself is allowed.
        assert_eq!(
            validated_new_window_days(days(MAX_BASELINE_NEW_WINDOW_DAYS as u64)).unwrap(),
            MAX_BASELINE_NEW_WINDOW_DAYS
        );
        // One day over → rejected, no panic.
        assert!(validated_new_window_days(days(MAX_BASELINE_NEW_WINDOW_DAYS as u64 + 1)).is_err());
        // The exact chrono-overflow value codex found → rejected, no panic.
        assert!(validated_new_window_days(days(106_751_992)).is_err());
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::schema::OcsfProfile;
    use crate::{DualPool, DualPoolConfig, SearchRequest, TimeRangeInput};
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Arc;

    async fn local() -> Option<SearchService> {
        let config = DualPoolConfig::with_auth(
            "postgres://nanosiem:nanosiem@localhost:5432/nanosiem",
            "http://localhost:8123",
            "nanosiem",
            "default",
            "",
        );
        match DualPool::new(&config).await {
            Ok(pool) => Some(SearchService::with_dual_pool_and_profile(
                &pool,
                Arc::new(OcsfProfile::new()),
            )),
            Err(e) => {
                eprintln!("Could not connect to local DBs ({e}); is the stack up?");
                None
            }
        }
    }

    fn req(query: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> SearchRequest {
        SearchRequest {
            query: query.to_string(),
            time_range: TimeRangeInput::new(start, end),
            limit: Some(200),
            offset: None,
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: Some("interactive".to_string()),
            dataset: None,
        }
    }

    /// Drives the full search() path for `| baseline` against the local stack.
    /// `#[ignore]` — requires local ClickHouse + Postgres. Run:
    ///   cargo test -p nanosiem-core --lib baseline_command_live -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "requires local ClickHouse + Postgres"]
    async fn baseline_command_live() {
        let Some(ss) = local().await else {
            return;
        };
        // Current window where ws-fin-001's new processes appear (2026-07-11 15:13).
        let start = Utc.with_ymd_and_hms(2026, 7, 11, 15, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 7, 11, 15, 28, 0).unwrap();

        for query in [
            "src_host=\"ws-fin-001.corp.local\" | baseline",
            "* | baseline host=\"ws-fin-001.corp.local\" window=7d",
        ] {
            println!("\n=== {query} ===");
            let resp = ss
                .search(req(query, start, end), &ScopeSet::unrestricted())
                .await
                .expect("search runs");
            assert_eq!(resp.display_type, Some(DisplayType::Baseline));
            assert!(
                !resp.results.is_empty(),
                "should return at least a summary row"
            );
            for row in &resp.results {
                println!("{}", serde_json::to_string(row).unwrap());
            }
        }
    }
}

/// NAN-3059: the lake baseline issues rollup-shaped activity reads and ONE
/// scan per dimension, folded back into per-value firsts.
#[cfg(test)]
mod lake_baseline_shape_tests {
    use super::*;

    #[test]
    fn activity_reads_are_single_field_rollup_shapes() {
        let queries = lake_baseline_activity_queries("host", "ws-1.corp.local").unwrap();
        assert_eq!(queries.len(), 2);
        for query in &queries {
            assert!(!query.contains(" OR "), "{query}");
            assert!(query.ends_with("| timechart span=1h count"), "{query}");
            crate::query::parse_query(query).expect("activity query parses");
        }
        assert!(lake_baseline_activity_queries("host", "a\"b'c").is_err());
    }

    #[test]
    fn one_window_read_folds_both_fields_into_per_value_firsts() {
        let query = lake_baseline_window_query(
            "(device.hostname=\"ws-1\")",
            &["user.name", "actor.user.name"],
        );
        crate::query::parse_query(&query).expect("window query parses");
        assert!(query.contains("by user.name, actor.user.name"), "{query}");
        let rows = vec![
            serde_json::json!({"user.name": "alice", "actor.user.name": "alice", "count": 3, "first_seen": "2026-09-29 10:00:00.000000"}),
            serde_json::json!({"user.name": null, "actor.user.name": "alice", "count": 2, "first_seen": "2026-09-28 09:00:00.000000"}),
            serde_json::json!({"user.name": "bob", "actor.user.name": "-", "count": 1, "first_seen": "2026-09-29 11:00:00.000000"}),
        ];
        let folded = fold_lake_baseline_dimension(&["user.name", "actor.user.name"], &rows);
        assert_eq!(folded.len(), 2);
        let alice = folded.iter().find(|(v, _, _)| v == "alice").unwrap();
        assert_eq!(
            alice.1, 5,
            "same value in two fields of one row counts once"
        );
        assert_eq!(alice.2.to_rfc3339(), "2026-09-28T09:00:00+00:00");
        assert!(folded.iter().any(|(v, c, _)| v == "bob" && *c == 1));
    }
}
