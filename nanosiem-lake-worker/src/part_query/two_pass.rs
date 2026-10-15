// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3155: narrow first pass for row-output shapes.
//!
//! A table-view row query that filters, sorts and limits (`host | sort -time
//! | head 50`, `* | where host=X | sort time | head 50`, `host` with a page
//! of 5,000, any sort key, either direction) used to decode every output
//! leaf (`raw_data`, `message`, two dozen display columns) of every row that
//! passed the predicate, only to keep the page. Two statements instead:
//!
//! 1. **Narrow**: the compiled pipeline unchanged except that stage 0 projects
//!    only the columns the predicates and orderings name, plus the storage
//!    function's row identity (`_path`, `_row_number`). Its output is the
//!    identity of every result row, in result order.
//! 2. **Payload**: the original statement, with stage 0 additionally fenced to
//!    exactly those identities (`(_path, _row_number) IN {ids}`, plus
//!    `time IN {times}` so Parquet statistics skip every other row group).
//!
//! Exactness. Projection never changes which rows a pipeline selects: every
//! stage is a row-local `WHERE`, an `ORDER BY` or a `LIMIT` over `SELECT *`
//! (anything else is refused by [`plan`]), so pass 1 computes exactly the
//! result row set R. Pass 2 runs the same stages over R alone: each `WHERE`
//! holds on every row of R (it held in pass 1), and each `LIMIT n` is at least
//! the number of rows reaching it (|R| never exceeds a later stage's limit,
//! since R passed every limit), so pass 2 returns R. Its rows are then put in
//! pass 1's order, which is the original statement's final `ORDER BY` (its
//! `metadata.uid` tie key makes it total). Ties inside an intermediate
//! `ORDER BY … LIMIT` are as non-deterministic as the one-pass statement was;
//! pass 2 never re-decides them. Any disagreement between the passes (a row
//! missing, an extra row) falls back to the one-pass statement.

use crate::planner::{self, CompiledQuery, RequiredColumn, ROW_NUMBER_COLUMN, ROW_PATH_COLUMN};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Pass 1's output columns.
pub const NARROW_PATH: &str = "__nano_row_path";
pub const NARROW_ROW: &str = "__nano_row_number";
pub const NARROW_TIME: &str = "__nano_row_time";
/// Pass 2's identity parameter.
pub const ROW_IDS_PARAM: &str = "nano_row_ids";
/// Rows fetched per payload statement (each statement fences at most this
/// many identities and exact times).
pub const MAX_PAYLOAD_ROWS: usize = planner::MAX_EXACT_FENCE_TIMES;
/// Pages beyond this are left to the one-pass statement.
pub const MAX_TWO_PASS_ROWS: usize = 20_000;

const SOURCE: &str = "__nano_lake_source__";
/// The compiler's deterministic event-order tie key on the final ORDER BY.
const UID_TIE: &str = ", \"metadata.uid\" DESC";

/// The two statements of one row query.
#[derive(Debug, Clone)]
pub struct TwoPass {
    /// Pass 1. Its final order drops the `metadata.uid` tie key (decoding
    /// every row's uid was most of its cost) and keeps every row tied with
    /// the last one (`LIMIT n WITH TIES`): a superset of the result whose
    /// excess rows all share the boundary instant.
    pub narrow: CompiledQuery,
    /// Pass 1 under a `(time, metadata.uid)` cursor, which names the uid:
    /// the exact final order and limit.
    pub narrow_cursor: CompiledQuery,
    /// Pass 2: the original statement fenced to pass 1's rows. It re-applies
    /// the final order and limit, so its output is the result, in order.
    pub payload: CompiledQuery,
    /// The original statement's final `LIMIT`.
    pub limit: usize,
    /// The final order is the compiler's event order (`time DESC,
    /// "metadata.uid" DESC`) and rows carry `metadata.uid`: payload batches
    /// can then be merged in that order.
    pub event_order: bool,
}

/// The compiler's deterministic event order.
pub const EVENT_ORDER: &str = "time DESC, \"metadata.uid\" DESC";

/// A parsed staged row pipeline (see the module docs).
struct Stages<'a> {
    /// Stage 0's projection list (plain identifiers).
    columns: &'a str,
    /// Byte range of stage 0's `WHERE ` keyword end, where a fence is spliced.
    where_at: usize,
    /// Byte offset at the end of stage 0's projection list.
    columns_end: usize,
    /// Final statement: `SELECT * FROM stage_N` start offset.
    final_at: usize,
    /// The last stage's name.
    last: String,
    /// Final `ORDER BY …` text (without the keyword) and `LIMIT`.
    final_order: &'a str,
    final_limit: usize,
    /// Text that may reference columns: stage 0's WHERE body, later stage
    /// clauses, the final ORDER BY.
    references: Vec<&'a str>,
}

fn rejected_operators() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Anything that is not a row-local predicate, a plain ordering or a plain
    // limit: aggregates over windows, row multiplication, nested statements,
    // set operations, non-deterministic or block-position functions.
    RE.get_or_init(|| Regex::new(
        r"(?i)\b(select|over|arrayjoin|array\s+join|join|union|intersect|except|group\s+by|having|qualify|window|distinct|with\s+ties|with\s+fill|limit\s+by|offset|interpolate|settings|rand\w*|now\w*|today|yesterday|generateuuid\w*|rownumberinblock|rownumberinallblocks|blocknumber|blocksize|runningdifference\w*|runningaccumulate|neighbor|ignore|sleep\w*|throwif|currentdatabase|hostname|uptime|_path|_row_number|_file)\b",
    ).expect("static regex"))
}

fn plain_columns() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^(?:[A-Za-z_][A-Za-z0-9_]*|"[A-Za-z_][A-Za-z0-9_.^]*")(?:, (?:[A-Za-z_][A-Za-z0-9_]*|"[A-Za-z_][A-Za-z0-9_.^]*"))*$"#)
        .expect("static regex"))
}

fn limit_clause() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^LIMIT ([0-9]{1,9})$").expect("static regex"))
}

/// Parse the compiler's staged row pipeline, or `None` for any other shape.
/// Markers are found on a copy with every quoted region blanked, so a string
/// literal or quoted identifier can neither fake nor hide one.
fn stages(sql: &str) -> Option<Stages<'_>> {
    let blank = blank_quoted(sql)?;
    if blank.contains(';') {
        return None;
    }
    let head = "WITH stage_0 AS (\n  SELECT ";
    if !blank.starts_with(head) {
        return None;
    }
    let from = format!(" FROM {SOURCE}\n  WHERE ");
    let columns_start = head.len();
    let columns_end = columns_start + blank[columns_start..].find(&from)?;
    let columns = &sql[columns_start..columns_end];
    if !plain_columns().is_match(columns) {
        return None;
    }
    let where_at = columns_end + from.len();
    let mut references = Vec::new();
    // Stage bodies: `stage_k AS (\n  <body>\n)` separated by `,\n`.
    let mut cursor = where_at;
    let mut stage = 0_usize;
    let mut body_start = where_at;
    let final_at;
    loop {
        let next = format!("\n),\nstage_{} AS (\n  SELECT * FROM stage_{stage}\n  ", stage + 1);
        let last = format!("\n)\nSELECT * FROM stage_{stage} ORDER BY ");
        let next_at = blank[cursor..].find(&next).map(|at| at + cursor);
        let last_at = blank[cursor..].find(&last).map(|at| at + cursor);
        let (end, is_last) = match (next_at, last_at) {
            (Some(next_at), Some(last_at)) if next_at < last_at => (next_at, false),
            (Some(next_at), None) => (next_at, false),
            (_, Some(last_at)) => (last_at, true),
            (None, None) => return None,
        };
        let body = &sql[body_start..end];
        let blank_body = &blank[body_start..end];
        if rejected_operators().is_match(blank_body) || blank_body.contains("stage_") {
            return None;
        }
        if stage == 0 {
            references.push(body);
        } else if let Some(clause) = body.strip_prefix("WHERE ") {
            references.push(clause);
        } else if let Some(clause) = body.strip_prefix("ORDER BY ") {
            references.push(clause);
        } else if !limit_clause().is_match(body) {
            return None;
        }
        if is_last {
            final_at = end + "\n)\n".len();
            break;
        }
        stage += 1;
        body_start = end + next.len();
        cursor = body_start;
        if stage > 64 {
            return None;
        }
    }
    let tail = &sql[final_at..];
    let blank_tail = &blank[final_at..];
    let prefix = format!("SELECT * FROM stage_{stage} ORDER BY ");
    let order_start = prefix.len();
    let settings = blank_tail.rfind(" SETTINGS ")?;
    let limit_at = blank_tail[..settings].rfind(" LIMIT ")?;
    let final_order = &tail[order_start..limit_at];
    let final_limit = tail[limit_at + " LIMIT ".len()..settings].trim().parse::<usize>().ok()?;
    if rejected_operators().is_match(&blank_tail[order_start..limit_at])
        || blank_tail[settings..].contains("stage_")
        || blank_tail[settings + " SETTINGS ".len()..].contains(['(', ')'])
    {
        return None;
    }
    references.push(final_order.strip_suffix(UID_TIE).unwrap_or(final_order));
    Some(Stages {
        columns,
        where_at,
        columns_end,
        final_at,
        last: format!("stage_{stage}"),
        final_order,
        final_limit,
        references,
    })
}

/// `sql` with every quoted region (delimiters included) replaced by spaces,
/// byte for byte, so offsets into it are offsets into `sql`. `None` on an
/// unterminated quote.
fn blank_quoted(sql: &str) -> Option<String> {
    let mut out = String::with_capacity(sql.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut chars = sql.chars().peekable();
    let blank = |out: &mut String, ch: char| out.extend(std::iter::repeat_n(' ', ch.len_utf8()));
    while let Some(ch) = chars.next() {
        match quote {
            None if matches!(ch, '\'' | '"' | '`') => { quote = Some(ch); out.push(' '); }
            None => out.push(ch),
            Some('\'') if escaped => { escaped = false; blank(&mut out, ch); }
            Some('\'') if ch == '\\' => { escaped = true; out.push(' '); }
            Some(delimiter) if ch == delimiter => {
                out.push(' ');
                if chars.peek() == Some(&delimiter) {
                    chars.next();
                    out.push(' ');
                } else {
                    quote = None;
                }
            }
            Some(_) => blank(&mut out, ch),
        }
    }
    (quote.is_none() && out.len() == sql.len()).then_some(out)
}

/// `SELECT <cols> FROM <source> WHERE <w> ORDER BY <o> LIMIT <n> SETTINGS <s>`
/// rewritten as the equivalent one-stage pipeline (`WITH stage_0 AS (SELECT
/// <cols> FROM <source> WHERE <w>) SELECT * FROM stage_0 ORDER BY <o> LIMIT
/// <n> SETTINGS <s>`), or `None` for any other text.
fn single_select_as_stages(sql: &str) -> Option<String> {
    let blank = blank_quoted(sql)?;
    if !blank.starts_with("SELECT ") || blank.matches("SELECT").count() != 1 || blank.contains('\n') {
        return None;
    }
    let from = format!(" FROM {SOURCE} WHERE ");
    let columns_end = blank.find(&from)?;
    let settings = blank.rfind(" SETTINGS ")?;
    let limit = blank[..settings].rfind(" LIMIT ")?;
    let order = blank[..limit].rfind(" ORDER BY ")?;
    let where_start = columns_end + from.len();
    if order < where_start {
        return None;
    }
    Some(format!(
        "WITH stage_0 AS (\n  SELECT {} FROM {SOURCE}\n  WHERE {}\n)\nSELECT * FROM stage_0 ORDER BY {} LIMIT {}{}",
        &sql["SELECT ".len()..columns_end],
        &sql[where_start..order],
        &sql[order + " ORDER BY ".len()..limit],
        &sql[limit + " LIMIT ".len()..settings],
        &sql[settings..],
    ))
}

fn identifier(name: &str) -> String {
    let simple = name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if simple { name.to_string() } else { format!("\"{name}\"") }
}

/// Is column `name` referenced in `text` (quoted, or as a bare word)?
fn references(text: &str, name: &str) -> bool {
    if text.contains(&format!("\"{name}\"")) || text.contains(&format!("`{name}`")) {
        return true;
    }
    if name.contains('.') || name.contains('^') {
        return false;
    }
    text.match_indices(name).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + name.len()..].chars().next();
        let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '"' || c == '`');
        !word(before) && !word(after)
    })
}

fn identity_columns() -> [RequiredColumn; 2] {
    [
        RequiredColumn { name: ROW_PATH_COLUMN.to_string(), field_type: "string".to_string() },
        RequiredColumn { name: ROW_NUMBER_COLUMN.to_string(), field_type: "long".to_string() },
    ]
}

/// The two statements of `compiled`, or `None` when its shape is not a
/// staged row pipeline whose output columns outnumber what it filters and
/// orders on (nothing to save).
pub fn plan(compiled: &CompiledQuery) -> Option<TwoPass> {
    // Operational kill switch: `NANO_LAKE_TWO_PASS=0` runs every row query
    // as one statement (the pre-NAN-3155 plan).
    if !crate::perf_overrides::probe_flag("two_pass", std::env::var("NANO_LAKE_TWO_PASS").as_deref() != Ok("0")) {
        return None;
    }
    if compiled.dataset != "logs" || !compiled.table_view || compiled.stats_page
        || compiled.required_columns.iter().any(|column| planner::is_row_identity_column(&column.name))
    {
        return None;
    }
    // A single-select page (`host` with a 5,000-row page) is the one-stage
    // pipeline it denotes.
    let staged;
    let compiled = match single_select_as_stages(&compiled.sql) {
        Some(sql) => {
            let mut copy = compiled.clone();
            copy.sql = sql;
            staged = copy;
            &staged
        }
        None => compiled,
    };
    let parsed = stages(&compiled.sql)?;
    if parsed.final_limit == 0 || parsed.final_limit > MAX_TWO_PASS_ROWS {
        return None;
    }
    let output = parsed.columns.split(", ").map(|column| column.trim_matches('"').to_string()).collect::<BTreeSet<_>>();
    // Every output column must be a typed required column (the payload's
    // projection), and the order key `time` must be present.
    if !output.contains("time")
        || !output.iter().all(|name| compiled.required_columns.iter().any(|column| column.name == *name))
    {
        return None;
    }
    let mut narrow_names = compiled.required_columns.iter()
        .map(|column| column.name.clone())
        .filter(|name| parsed.references.iter().any(|text| references(text, name)))
        .collect::<BTreeSet<_>>();
    narrow_names.insert("time".to_string());
    if !narrow_names.iter().all(|name| compiled.required_columns.iter().any(|column| column.name == *name)) {
        return None;
    }
    let narrow_output = narrow_names.iter().filter(|name| output.contains(*name)).count();
    if narrow_output >= output.len() {
        return None;
    }
    let sql = &compiled.sql;
    let settings = &sql[sql.rfind(" SETTINGS ")?..];
    let narrow_statement = |names: &BTreeSet<String>, order: &str, ties: bool| {
        let columns = names.iter().map(|name| identifier(name))
            .chain([ROW_PATH_COLUMN.to_string(), ROW_NUMBER_COLUMN.to_string()])
            .collect::<Vec<_>>().join(", ");
        let mut narrow = compiled.clone();
        narrow.sql = format!(
            "{}{columns}{}SELECT {ROW_PATH_COLUMN} AS {NARROW_PATH}, {ROW_NUMBER_COLUMN} AS {NARROW_ROW}, time AS {NARROW_TIME} FROM {} ORDER BY {order} LIMIT {}{}{settings}",
            &sql[..parsed.columns_end - parsed.columns.len()],
            &sql[parsed.columns_end..parsed.final_at],
            parsed.last,
            parsed.final_limit,
            if ties { " WITH TIES" } else { "" },
        );
        narrow.newest_first_event_rows = false;
        narrow.required_columns.retain(|column| names.contains(&column.name));
        narrow.required_columns.extend(identity_columns());
        narrow.projected_scan_columns.retain(|path| names.contains(path));
        narrow
    };
    // Without the uid tie key the narrow order is a prefix of the final
    // order: WITH TIES keeps every row that could win the tie.
    let untied = parsed.final_order.strip_suffix(UID_TIE).filter(|_| !narrow_names.contains("metadata.uid"));
    let narrow = match untied {
        Some(order) => narrow_statement(&narrow_names, order, true),
        None => narrow_statement(&narrow_names, parsed.final_order, false),
    };
    let mut cursor_names = narrow_names.clone();
    cursor_names.insert("metadata.uid".to_string());
    if !compiled.required_columns.iter().any(|column| column.name == "metadata.uid") {
        return None;
    }
    let narrow_cursor = narrow_statement(&cursor_names, parsed.final_order, false);

    let mut payload = compiled.clone();
    payload.sql = format!(
        "{}, {ROW_PATH_COLUMN}, {ROW_NUMBER_COLUMN}{}({ROW_PATH_COLUMN}, {ROW_NUMBER_COLUMN}) IN {{{ROW_IDS_PARAM}:Array(Tuple(String, Int64))}} AND {}",
        &sql[..parsed.columns_end],
        &sql[parsed.columns_end..parsed.where_at],
        &sql[parsed.where_at..],
    );
    payload.newest_first_event_rows = false;
    payload.required_columns.extend(identity_columns());
    let event_order = parsed.final_order == EVENT_ORDER && output.contains("metadata.uid");
    Some(TwoPass { narrow, narrow_cursor, payload, limit: parsed.final_limit, event_order })
}

/// One pass-1 row: its identity and its event time (exact fence form).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RowId {
    pub path: String,
    pub row: i64,
}

/// Pass 2's identity parameter value for `ids`.
pub fn ids_param(ids: &[RowId]) -> String {
    let quote = |value: &str| value.replace('\\', "\\\\").replace('\'', "\\'");
    format!("[{}]", ids.iter().map(|id| format!("('{}',{})", quote(&id.path), id.row)).collect::<Vec<_>>().join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled(sql: &str, columns: &[&str]) -> CompiledQuery {
        CompiledQuery {
            schema_version: 1,
            profile: "ocsf".into(),
            dataset: "logs".into(),
            source_placeholder: SOURCE.into(),
            query_sha256: "0".repeat(64),
            start: "2026-09-30T16:00:00Z".into(),
            end: "2026-10-01T16:00:00Z".into(),
            limit: 101,
            table_view: true,
            newest_first_event_rows: true,
            stats_page: false,
            candidate_hints: Vec::new(),
            required_columns: columns.iter().map(|name| RequiredColumn {
                name: name.to_string(),
                field_type: if *name == "time" { "timestamp".into() } else { "string".into() },
            }).collect(),
            projected_scan_columns: vec!["device.hostname".into(), "time".into()],
            sql: sql.into(),
        }
    }

    const COLUMNS: &[&str] = &["device.hostname", "message", "metadata.uid", "raw_data", "time", "actor.user.name"];

    fn where_host(order: &str) -> String {
        format!("WITH stage_0 AS (\n  SELECT \"device.hostname\", message, \"metadata.uid\", raw_data, time FROM __nano_lake_source__\n  WHERE time BETWEEN '2026-09-30 16:00:00.000000' AND '2026-10-01 16:00:00.000000'\n  AND (1)\n),\nstage_1 AS (\n  SELECT * FROM stage_0\n  WHERE \"device.hostname\" = 'ws-1'\n),\nstage_2 AS (\n  SELECT * FROM stage_1\n  ORDER BY {order}\n),\nstage_3 AS (\n  SELECT * FROM stage_2\n  LIMIT 50\n)\nSELECT * FROM stage_3 ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 101 SETTINGS max_threads=16, max_execution_time=300")
    }

    #[test]
    fn staged_where_sort_head_reads_only_predicate_and_order_columns_first() {
        for order in ["time DESC", "time ASC", "\"actor.user.name\" ASC, time DESC"] {
            let query = compiled(&where_host(order), COLUMNS);
            let plan = plan(&query).expect("staged row pipeline");
            let narrow = &plan.narrow.sql;
            assert!(narrow.starts_with("WITH stage_0 AS (\n  SELECT \"device.hostname\", time, _path, _row_number FROM __nano_lake_source__\n")
                || order.contains("actor"), "{narrow}");
            assert!(!narrow.contains("raw_data") && !narrow.contains("message") && !narrow.contains("metadata.uid"), "{narrow}");
            assert!(narrow.contains(&format!("ORDER BY {order}")), "every stage is kept: {narrow}");
            assert!(narrow.contains("LIMIT 50"));
            // The uid tie key is dropped; every row tied at the boundary
            // instant is kept for the payload's exact final order.
            assert!(narrow.ends_with("SELECT _path AS __nano_row_path, _row_number AS __nano_row_number, time AS __nano_row_time FROM stage_3 ORDER BY time DESC LIMIT 101 WITH TIES SETTINGS max_threads=16, max_execution_time=300"), "{narrow}");
            let cursor = &plan.narrow_cursor.sql;
            assert!(cursor.contains("\"metadata.uid\", time, _path") && cursor.ends_with("ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 101 SETTINGS max_threads=16, max_execution_time=300"), "{cursor}");
            assert!(plan.narrow_cursor.required_columns.iter().any(|c| c.name == "metadata.uid"));
            assert_eq!(plan.limit, 101);
            assert!(plan.event_order);
            assert_eq!(order.contains("actor"), plan.narrow.required_columns.iter().any(|c| c.name == "actor.user.name"));
            assert!(plan.narrow.required_columns.iter().any(|c| c.name == "_path"));
            assert!(!plan.narrow.required_columns.iter().any(|c| c.name == "raw_data"));
            let payload = &plan.payload.sql;
            assert!(payload.contains("SELECT \"device.hostname\", message, \"metadata.uid\", raw_data, time, _path, _row_number FROM __nano_lake_source__\n  WHERE (_path, _row_number) IN {nano_row_ids:Array(Tuple(String, Int64))} AND time BETWEEN"), "{payload}");
            assert!(payload.ends_with(&query.sql[query.sql.find("\n  AND (1)").unwrap()..]), "the rest of the statement is unchanged");
        }
    }

    #[test]
    fn search_term_sort_head_and_plain_limit_are_two_pass() {
        let sort_head = "WITH stage_0 AS (\n  SELECT \"device.hostname\", message, \"metadata.uid\", time FROM __nano_lake_source__\n  WHERE time BETWEEN '2026-09-30 16:00:00.000000' AND '2026-10-01 16:00:00.000000'\n  AND (\"device.hostname\" = 'ws-1')\n),\nstage_1 AS (\n  SELECT * FROM stage_0\n  ORDER BY time DESC\n),\nstage_2 AS (\n  SELECT * FROM stage_1\n  LIMIT 2000\n)\nSELECT * FROM stage_2 ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 2000 SETTINGS max_threads=16";
        assert!(plan(&compiled(sort_head, COLUMNS)).is_some());
        let plain = "WITH stage_0 AS (\n  SELECT \"device.hostname\", message, \"metadata.uid\", raw_data, time FROM __nano_lake_source__\n  WHERE time BETWEEN '2026-09-30 16:00:00.000000' AND '2026-10-01 16:00:00.000000'\n  AND (1)\n),\nstage_1 AS (\n  SELECT * FROM stage_0\n  WHERE \"device.hostname\" = 'ws-1'\n)\nSELECT * FROM stage_1 ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 5001 SETTINGS max_threads=16";
        let plan = plan(&compiled(plain, COLUMNS)).unwrap();
        assert!(plan.narrow.sql.contains("FROM stage_1 ORDER BY time DESC LIMIT 5001 WITH TIES"));
    }

    #[test]
    fn non_row_shapes_and_disguised_markers_are_refused() {
        let base = where_host("time DESC");
        let refuse = |sql: String| assert!(plan(&compiled(&sql, COLUMNS)).is_none(), "{sql}");
        // Aggregation, eval, window, nested select, row multiplication.
        refuse(base.replace("  ORDER BY time DESC", "  GROUP BY time"));
        refuse(base.replace("SELECT \"device.hostname\", message", "SELECT lower(\"device.hostname\") AS h, message"));
        refuse(base.replace("= 'ws-1'", "IN (SELECT 1)"));
        refuse(base.replace("= 'ws-1'", "= 'ws-1' AND arrayJoin([1, 2]) = 1"));
        refuse(base.replace("LIMIT 50\n", "LIMIT 50 OFFSET 5\n"));
        refuse(base.replace("= 'ws-1'", "= 'ws-1' AND rand() > 0"));
        refuse(base.replace("  LIMIT 50\n", "  SELECT count() FROM stage_2\n"));
        // A literal cannot fake the stage markers: it stays a literal.
        let literal = "= '\n),\nstage_2 AS (\n  SELECT * FROM stage_1\n  '";
        let faked = plan(&compiled(&base.replace("= 'ws-1'", literal), COLUMNS)).unwrap();
        assert!(faked.narrow.sql.contains(literal) && faked.narrow.sql.contains(" FROM stage_3 ORDER BY"), "{}", faked.narrow.sql);
        // Not a table view, a stats page, or already a two-pass statement.
        let mut query = compiled(&base, COLUMNS);
        query.table_view = false;
        assert!(plan(&query).is_none());
        let mut query = compiled(&base, COLUMNS);
        query.stats_page = true;
        assert!(plan(&query).is_none());
        let plan = plan(&compiled(&base, COLUMNS)).unwrap();
        assert!(super::plan(&plan.narrow).is_none() && super::plan(&plan.payload).is_none() && super::plan(&plan.narrow_cursor).is_none());
        // Nothing to save: the output is exactly the predicate/order columns.
        let narrow_only = base.replace("\"device.hostname\", message, \"metadata.uid\", raw_data, time FROM", "\"device.hostname\", time FROM");
        refuse(narrow_only);
    }

    #[test]
    fn single_select_page_is_its_one_stage_pipeline() {
        let sql = "SELECT \"device.hostname\", message, \"metadata.uid\", raw_data, time FROM __nano_lake_source__ WHERE time BETWEEN '2026-09-30 16:00:00.000000' AND '2026-10-01 16:00:00.000000' AND (\"device.hostname\" = 'a ORDER BY b LIMIT 3') ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 5001 SETTINGS max_threads=16";
        assert_eq!(single_select_as_stages(sql).unwrap(), "WITH stage_0 AS (\n  SELECT \"device.hostname\", message, \"metadata.uid\", raw_data, time FROM __nano_lake_source__\n  WHERE time BETWEEN '2026-09-30 16:00:00.000000' AND '2026-10-01 16:00:00.000000' AND (\"device.hostname\" = 'a ORDER BY b LIMIT 3')\n)\nSELECT * FROM stage_0 ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 5001 SETTINGS max_threads=16");
        let plan = plan(&compiled(sql, COLUMNS)).unwrap();
        assert!(plan.narrow.sql.contains("SELECT \"device.hostname\", time, _path, _row_number FROM __nano_lake_source__"), "{}", plan.narrow.sql);
        assert!(plan.narrow.sql.contains("FROM stage_0 ORDER BY time DESC LIMIT 5001 WITH TIES SETTINGS"), "{}", plan.narrow.sql);
        assert!(single_select_as_stages("SELECT count() FROM __nano_lake_source__ WHERE x IN (SELECT 1) ORDER BY time DESC LIMIT 1 SETTINGS a=1").is_none());
    }

    #[test]
    fn identity_parameter_escapes_paths() {
        let ids = [RowId { path: "/cache/a'b.parquet".into(), row: 7 }, RowId { path: "/c\\d".into(), row: 0 }];
        assert_eq!(ids_param(&ids), "[('/cache/a\\'b.parquet',7),('/c\\\\d',0)]");
    }
}
