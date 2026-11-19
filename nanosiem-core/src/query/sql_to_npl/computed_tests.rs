// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5630: computed columns and the other shapes the hunts investigator
//! writes. Each realistic shape has a corpus entry (what it converts to, and
//! whether the proof calls it exact); each equivalence the comparator
//! accepts has a near miss it must NOT call exact.

use chrono::{TimeZone, Utc};

use super::*;
use crate::schema::{profile_for_id, SchemaId};

const W: &str = "timestamp >= {earliest:DateTime64(6, 'UTC')} AND timestamp <= {latest:DateTime64(6, 'UTC')}";

fn ocsf() -> ConvertContext {
    ConvertContext::new(profile_for_id(SchemaId::Ocsf))
}

fn sql(body: &str) -> String {
    body.replace("{W}", W)
}

/// The conversion of `body`, which must be exact, and its nPL.
fn exact(body: &str) -> String {
    let r = convert_sql_to_npl(&sql(body), &ocsf());
    assert!(r.unsupported.is_none(), "{body}: refused: {:?}", r.unsupported);
    assert!(r.exact, "{body} → {:?}: {:#?}", r.npl, r.differences);
    r.npl.expect("npl")
}

/// The conversion of `body`, which must convert but NOT be exact; the
/// differences must name `why`.
fn approximate(body: &str, why: &str) -> SqlToNpl {
    let r = convert_sql_to_npl(&sql(body), &ocsf());
    assert!(r.unsupported.is_none(), "{body}: refused: {:?}", r.unsupported);
    assert!(!r.exact, "{body} → {:?} was called exact", r.npl);
    let all = r.differences.iter().map(|d| d.detail.as_str()).collect::<Vec<_>>().join(" | ");
    assert!(all.contains(why), "{body}: the differences do not say `{why}`: {all}");
    r
}

/// The investigator's shapes (its prompt's "SHAPES THAT ANSWER MOST
/// QUESTIONS" plus what it writes around them), with the nPL each converts
/// to exactly.
#[test]
fn the_investigator_shapes_convert_exactly() {
    for (body, npl) in [
        // A computed group key.
        (
            "SELECT lower(`actor.user.name`) AS u, count() AS n, min(timestamp) AS t0, max(timestamp) AS t1 FROM ocsf_logs WHERE {W} AND class_uid = 3002 AND status_id = 2 GROUP BY u ORDER BY n DESC LIMIT 20",
            "class_uid=3002 status_id=2 | eval u=lower(actor.user.name) | stats count() as n, min(timestamp) as t0, max(timestamp) as t1 by u | sort -n | head 20",
        ),
        // Cadence: a 5-minute bucket is `bin`.
        (
            "SELECT toStartOfInterval(timestamp, INTERVAL 5 minute) AS b, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 4001 AND `dst_endpoint.ip` = '203.0.113.66' GROUP BY b ORDER BY b LIMIT 200",
            "class_uid=4001 dst_endpoint.ip=\"203.0.113.66\" | bin timestamp span=5m as b | stats count() as n by b | sort b | head 200",
        ),
        (
            "SELECT toStartOfHour(timestamp) AS hour, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 3002 GROUP BY hour ORDER BY hour",
            "class_uid=3002 | bin timestamp span=1h as hour | stats count() as n by hour | sort hour",
        ),
        // An unnamed computed key gets a name of its own.
        (
            "SELECT toStartOfHour(timestamp), count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 3002 GROUP BY toStartOfHour(timestamp) ORDER BY toStartOfHour(timestamp)",
            "class_uid=3002 | bin timestamp span=1h as tostartofhour_timestamp | stats count() as n by tostartofhour_timestamp | sort tostartofhour_timestamp",
        ),
        (
            "SELECT toHour(timestamp) AS hr, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 3002 AND status_id = 1 GROUP BY hr ORDER BY hr LIMIT 24",
            "class_uid=3002 status_id=1 | eval hr=hour(timestamp) | stats count() as n by hr | sort hr | head 24",
        ),
        // Labels: if / multiIf / CASE.
        (
            "SELECT if(status_id = 2, 'failure', 'success') AS outcome, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 3002 GROUP BY outcome ORDER BY n DESC LIMIT 10",
            "class_uid=3002 | eval outcome=if(status_id=2, \"failure\", \"success\") | stats count() as n by outcome | sort -n | head 10",
        ),
        (
            "SELECT multiIf(`dst_endpoint.port` = 443, 'https', `dst_endpoint.port` = 80, 'http', 'other') AS svc, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 4001 GROUP BY svc ORDER BY n DESC LIMIT 10",
            "class_uid=4001 | eval svc=case(dst_endpoint.port=443, \"https\", dst_endpoint.port=80, \"http\", true, \"other\") | stats count() as n by svc | sort -n | head 10",
        ),
        (
            "SELECT CASE WHEN `dst_endpoint.port` = 443 THEN 'https' ELSE 'other' END AS svc, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 4001 GROUP BY svc",
            "class_uid=4001 | eval svc=case(dst_endpoint.port=443, \"https\", true, \"other\") | stats count() as n by svc",
        ),
        // A case-insensitive test inside an eval: nPL folds case as lower() does.
        (
            "SELECT if(lower(`process.name`) = 'cmd.exe', 'shell', 'other') AS kind, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 1007 GROUP BY kind",
            "class_uid=1007 | eval kind=if(process.name=\"cmd.exe\", \"shell\", \"other\") | stats count() as n by kind",
        ),
        (
            "SELECT concat(`actor.user.name`, '@', `device.hostname`) AS who, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 3002 GROUP BY who ORDER BY n DESC LIMIT 20",
            "class_uid=3002 | eval who=concat(actor.user.name, \"@\", device.hostname) | stats count() as n by who | sort -n | head 20",
        ),
        // URL / domain helpers.
        (
            "SELECT domain(`http_request.url.url_string`) AS d, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 4002 GROUP BY d ORDER BY n DESC LIMIT 20",
            "class_uid=4002 | eval d=extract_domain(http_request.url.url_string) | stats count() as n by d | sort -n | head 20",
        ),
        (
            "SELECT splitByChar('\\\\', `actor.user.name`)[1] AS dom, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 3002 GROUP BY dom ORDER BY n DESC LIMIT 20",
            "class_uid=3002 | eval dom=mvindex(split(actor.user.name, \"\\\\\"), 0) | stats count() as n by dom | sort -n | head 20",
        ),
        // Aggregates over a computed value: a hidden eval, one per expression.
        (
            "SELECT `query.hostname` AS q, avg(length(`query.hostname`)) AS avg_len, max(length(`query.hostname`)) AS max_len, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 4003 GROUP BY q ORDER BY avg_len DESC LIMIT 20",
            "class_uid=4003 | eval _x1=len(query.hostname) | stats avg(_x1) as avg_len, max(_x1) as max_len, count() as n by query.hostname | sort -avg_len | head 20",
        ),
        // A computed filter; a computed row column sorted on.
        (
            "SELECT id, timestamp, `device.hostname`, length(`process.cmd_line`) AS cmd_len FROM ocsf_logs WHERE {W} AND class_uid = 1007 AND length(`process.cmd_line`) > 1000 ORDER BY cmd_len DESC LIMIT 20",
            "class_uid=1007 | eval cmd_len=len(process.cmd_line) | where len(process.cmd_line)>1000 | sort -cmd_len | head 20 | table id, timestamp, device.hostname, cmd_len",
        ),
        (
            "SELECT id, timestamp, `device.hostname`, length(`process.cmd_line`) AS cmd_len FROM ocsf_logs WHERE {W} AND class_uid = 1007 AND cmd_len > 1000 ORDER BY cmd_len DESC LIMIT 20",
            "class_uid=1007 | eval cmd_len=len(process.cmd_line) | where cmd_len>1000 | sort -cmd_len | head 20 | table id, timestamp, device.hostname, cmd_len",
        ),
        (
            "SELECT `query.hostname`, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 4003 AND length(`query.hostname`) > 50 GROUP BY `query.hostname` ORDER BY n DESC LIMIT 20",
            "class_uid=4003 | where len(query.hostname)>50 | stats count() as n by query.hostname | sort -n | head 20",
        ),
        (
            "SELECT `device.hostname`, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 1007 AND countIf(length(`process.cmd_line`) > 1000) > 0 GROUP BY `device.hostname`",
            "",
        ),
        // Expressions over aggregates: an eval after stats.
        (
            "SELECT `actor.user.name`, count() AS n, countIf(status_id = 2) / count() AS fail_ratio FROM ocsf_logs WHERE {W} AND class_uid = 3002 GROUP BY `actor.user.name` ORDER BY fail_ratio DESC LIMIT 20",
            "class_uid=3002 | stats count() as n, count(eval(status_id=2)) as _a1 by actor.user.name | eval fail_ratio=(_a1 / n) | sort -fail_ratio | head 20 | fields - _a1",
        ),
        (
            "SELECT `device.hostname`, round(avg(`traffic.bytes_out`)) AS avg_out, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 4001 GROUP BY `device.hostname` ORDER BY avg_out DESC LIMIT 20",
            "class_uid=4001 | stats count() as n, avg(traffic.bytes_out) as _a1 by device.hostname | eval avg_out=round(_a1) | sort -avg_out | head 20 | fields - _a1",
        ),
        // A conditional count over a computed test.
        (
            "SELECT `device.hostname`, countIf(length(`process.cmd_line`) > 1000) AS long_cmds FROM ocsf_logs WHERE {W} AND class_uid = 1007 GROUP BY `device.hostname`",
            "class_uid=1007 | stats count(eval(len(process.cmd_line)>1000)) as long_cmds by device.hostname",
        ),
        // ORDER BY / HAVING an aggregate the SELECT does not return.
        (
            "SELECT `process.name`, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 1007 GROUP BY `process.name` HAVING min(timestamp) > '2026-11-17 00:00:00' ORDER BY max(timestamp) DESC LIMIT 20",
            "class_uid=1007 | stats count() as n, min(timestamp) as _a1, max(timestamp) as _a2 by process.name | where _a1>\"2026-11-17 00:00:00\" | sort -_a2 | head 20 | fields - _a1, _a2",
        ),
        (
            "SELECT lower(`process.name`) AS proc, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 1007 GROUP BY proc ORDER BY count() DESC LIMIT 20",
            "class_uid=1007 | eval proc=lower(process.name) | stats count() as n by proc | sort -n | head 20",
        ),
        // Positional GROUP BY / ORDER BY (on by default in ClickHouse).
        (
            "SELECT `device.hostname`, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 1007 GROUP BY 1 ORDER BY 2 DESC LIMIT 20",
            "class_uid=1007 | stats count() as n by device.hostname | sort -n | head 20",
        ),
        // A substring test spelled with position().
        (
            "SELECT `device.hostname`, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 1007 AND positionCaseInsensitive(`process.cmd_line`, 'lsass') > 0 GROUP BY `device.hostname` ORDER BY n DESC LIMIT 20",
            "class_uid=1007 process.cmd_line CONTAINS \"lsass\" | stats count() as n by device.hostname | sort -n | head 20",
        ),
        // A computed value of the keys, next to them.
        (
            "SELECT `device.hostname` AS host, upper(`device.hostname`) AS shout, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 1007 GROUP BY host",
            "class_uid=1007 | stats count() as n by device.hostname | eval shout=upper(device.hostname)",
        ),
    ] {
        if npl.is_empty() {
            // An aggregate in WHERE: ClickHouse refuses it, so does the converter.
            assert!(convert_sql_to_npl(&sql(body), &ocsf()).unsupported.is_some(), "{body}");
            continue;
        }
        assert_eq!(exact(body), npl, "{body}");
    }
}

/// What is close but not the same converts, never exact, and says why.
#[test]
fn close_computed_columns_are_approximate_with_a_reason() {
    // nPL computes + - * in Float64; SQL keeps the integer type.
    approximate(
        "SELECT `dst_endpoint.ip`, `traffic.bytes_out` * 8 AS bits FROM ocsf_logs WHERE {W} AND class_uid = 4001 LIMIT 5",
        "tofloat(",
    );
    // A time difference: nPL subtracts float parses of the times.
    approximate(
        "SELECT `src_endpoint.ip`, max(timestamp) - min(timestamp) AS span_s, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 4001 GROUP BY `src_endpoint.ip` ORDER BY span_s DESC LIMIT 20",
        "(max(timestamp) - min(timestamp))",
    );
    // to_date() is a NULL-on-overflow cast, toDate() is not.
    approximate(
        "SELECT toDate(timestamp) AS day, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 1007 GROUP BY day ORDER BY day",
        "accuratecastornull",
    );
    // A one-day toStartOfInterval is a Date; nPL's 1d bin is a DateTime.
    approximate(
        "SELECT toStartOfInterval(timestamp, INTERVAL 1 day) AS d, count() AS n FROM ocsf_logs WHERE {W} AND class_uid = 1007 GROUP BY d",
        "group by",
    );
    // An empty value is a distinct value to uniq(); nPL's dc() skips it.
    approximate(
        "SELECT toStartOfInterval(timestamp, INTERVAL 1 hour) AS h, uniq(`device.hostname`) AS hosts FROM ocsf_logs WHERE {W} AND class_uid = 1007 GROUP BY h ORDER BY h LIMIT 200",
        "skips them",
    );
}

/// Every equivalence the comparator accepts, against the near miss it must
/// refuse to call exact.
#[test]
fn computed_near_misses_are_never_called_exact() {
    let ctx = ocsf();
    let not_exact = |body: &str, npl: &str| {
        let s = sql(body);
        let d = compare_npl_with_sql(&s, npl, &ctx).unwrap_or_else(|e| panic!("{body} / {npl}: {e}"));
        assert!(!d.is_empty(), "`{npl}` was called exact for {body}");
    };
    let is_exact = |body: &str, npl: &str| {
        let s = sql(body);
        let d = compare_npl_with_sql(&s, npl, &ctx).unwrap_or_else(|e| panic!("{body} / {npl}: {e}"));
        assert!(d.is_empty(), "`{npl}` for {body}: {d:?}");
    };
    let g = |key: &str| {
        format!("SELECT {key} AS k, count() AS n FROM ocsf_logs WHERE {{W}} AND class_uid = 1007 GROUP BY k")
    };
    let n = |eval: &str| format!("class_uid=1007 | {eval} | stats count() as n by k");

    // lowerUTF8 folds non-ASCII letters; nPL's lower() (ClickHouse lower) does not.
    is_exact(&g("lower(`process.name`)"), &n("eval k=lower(process.name)"));
    not_exact(&g("lowerUTF8(`process.name`)"), &n("eval k=lower(process.name)"));
    // length counts bytes, lengthUTF8 characters.
    not_exact(&g("lengthUTF8(`process.name`)"), &n("eval k=len(process.name)"));
    // A case-sensitive SQL test is not nPL's case-insensitive one.
    not_exact(&g("if(`process.name` = 'cmd.exe', 1, 0)"), &n("eval k=if(process.name=\"cmd.exe\", 1, 0)"));
    not_exact(&g("if(`process.name` = 'CMD.exe', 1, 0)"), &n("eval k=if(process.name=\"CMD.exe\", 1, 0)"));
    // A different bucket width, a day bucket, and a width that does not
    // divide a day (where epoch- and day-aligned buckets differ).
    is_exact(&g("toStartOfInterval(timestamp, INTERVAL 10 minute)"), &n("bin timestamp span=10m as k"));
    not_exact(&g("toStartOfInterval(timestamp, INTERVAL 10 minute)"), &n("bin timestamp span=5m as k"));
    not_exact(&g("toStartOfInterval(timestamp, INTERVAL 1 day)"), &n("bin timestamp span=1d as k"));
    is_exact(&g("toStartOfInterval(timestamp, INTERVAL 7 minute)"), &n("bin timestamp span=7m as k"));
    not_exact(&g("toStartOfInterval(timestamp, INTERVAL 420 second)"), &n("bin timestamp span=7m as k"));
    // multiIf: the else value matters, and a missing else is NULL.
    not_exact(&g("multiIf(`dst_endpoint.port` = 443, 'https', 'web')"), &n("eval k=case(dst_endpoint.port=443, \"https\", true, \"other\")"));
    not_exact(&g("multiIf(`dst_endpoint.port` = 443, 'https', 'other')"), &n("eval k=case(dst_endpoint.port=443, \"https\")"));
    // splitByChar's subscript is 1-based; mvindex's 0-based.
    not_exact(&g("splitByChar('.', `query.hostname`)[1]"), &n("eval k=mvindex(split(query.hostname, \".\"), 1)"));
    // IS NULL is not nPL's isnull() (which also matches an empty value).
    not_exact(&g("if(`process.name` IS NULL, 1, 0)"), &n("eval k=if(isnull(process.name), 1, 0)"));
    // As a value, toString(x) is a string: it groups like x but sorts as text.
    not_exact(
        "SELECT toString(`dst_endpoint.port`) AS k, count() AS n FROM ocsf_logs WHERE {W} GROUP BY k ORDER BY k",
        "* | stats count() as n by dst_endpoint.port | sort dst_endpoint.port",
    );
    // A different argument, a different function.
    not_exact(&g("domain(`url.url_string`)"), &n("eval k=extract_root_domain(url.url_string)"));
    not_exact(&g("concat(`actor.user.name`, '@')"), &n("eval k=concat(actor.user.name, \"#\")"));
    // A filter on a computed value: the value and the bound both matter.
    not_exact(
        "SELECT id FROM ocsf_logs WHERE {W} AND length(`process.cmd_line`) > 1000",
        "* | where len(process.cmd_line)>100 | table id",
    );
    not_exact(
        "SELECT id FROM ocsf_logs WHERE {W} AND lengthUTF8(`process.cmd_line`) > 1000",
        "* | where len(process.cmd_line)>1000 | table id",
    );
    // A case-sensitive position() is broader in nPL (CONTAINS folds case).
    let r = convert_sql_to_npl(
        &sql("SELECT id FROM ocsf_logs WHERE {W} AND position(`process.cmd_line`, 'LSASS') > 0"),
        &ctx,
    );
    assert!(!r.exact && r.differences.iter().all(|d| d.kind == DifferenceKind::Broader), "{r:?}");
    // A post-stats ratio: the operands matter.
    not_exact(
        "SELECT `actor.user.name`, countIf(status_id = 2) / count() AS r FROM ocsf_logs WHERE {W} GROUP BY `actor.user.name`",
        "* | stats count(eval(status_id=1)) as _a1, count() as _a2 by actor.user.name | eval r=_a1/_a2 | fields - _a1, _a2",
    );
    // A hidden helper aggregate left in the output is an extra column.
    not_exact(
        "SELECT `process.name`, count() AS n FROM ocsf_logs WHERE {W} GROUP BY `process.name` HAVING max(timestamp) > '2026-11-17 00:00:00'",
        "* | stats count() as n, max(timestamp) as _a1 by process.name | where _a1>\"2026-11-17 00:00:00\"",
    );
}

/// NAN-5608 P2-19: what the comparator drops or does not model is a
/// difference, whoever wrote the nPL (the AI fallback compares its nPL the
/// same way).
#[test]
fn unmodeled_sql_is_never_called_exact() {
    let ctx = ocsf();
    for (body, npl) in [
        ("SELECT `process.name`, count() AS n FROM ocsf_logs WHERE {W} GROUP BY `process.name` WITH ROLLUP", "* | stats count() as n by process.name"),
        ("SELECT `process.name`, count() AS n FROM ocsf_logs WHERE {W} GROUP BY `process.name` WITH TOTALS", "* | stats count() as n by process.name"),
        ("SELECT id FROM ocsf_logs SAMPLE 0.1 WHERE {W} AND class_uid = 1007", "class_uid=1007 | table id"),
        ("SELECT id FROM ocsf_logs WHERE timestamp >= now() - INTERVAL 1 DAY AND class_uid = 1007", "class_uid=1007 | table id"),
        ("SELECT id FROM ocsf_logs WHERE {W} AND timestamp >= {latest:DateTime64(6, 'UTC')} - INTERVAL 1 HOUR AND class_uid = 1007", "class_uid=1007 | table id"),
        ("SELECT id FROM ocsf_logs WHERE timestamp >= 1763337600 AND class_uid = 1007", "class_uid=1007 | table id"),
    ] {
        let d = compare_npl_with_sql(&sql(body), npl, &ctx).unwrap_or_else(|e| panic!("{body}: {e}"));
        assert!(!d.is_empty(), "{body} was called exact");
    }
    // The literal-instant forms Search does run over stay exact.
    for body in [
        "SELECT id FROM ocsf_logs WHERE timestamp >= '2026-11-17 00:00:00' AND timestamp < toDateTime64('2026-11-18 00:00:00', 6) AND class_uid = 1007",
        "SELECT id FROM ocsf_logs WHERE {W} AND class_uid = 1007",
    ] {
        let d = compare_npl_with_sql(&sql(body), "class_uid=1007 | table id", &ctx).expect("compares");
        assert!(d.is_empty(), "{body}: {d:?}");
    }
}

/// NAN-5630: the hunt prompt teaches an extra literal bound next to the
/// window. The Search range is the tighter of the two.
#[test]
fn an_extra_bound_narrows_the_window() {
    let r = convert_sql_to_npl(
        &sql("SELECT id, timestamp, `process.cmd_line` FROM ocsf_logs WHERE {W} AND timestamp >= '2026-11-17 12:37:50' AND class_uid = 1007 ORDER BY timestamp LIMIT 20"),
        &ocsf(),
    );
    assert!(r.exact, "{r:?}");
    let narrow = Utc.with_ymd_and_hms(2026, 11, 17, 12, 37, 50).unwrap();
    let (start, end) = (Utc.with_ymd_and_hms(2026, 11, 17, 0, 0, 0).unwrap(), Utc.with_ymd_and_hms(2026, 11, 18, 0, 0, 0).unwrap());
    assert_eq!(resolve_bound(r.earliest.as_ref(), Some(start), Some(end)), Some(narrow));
    assert_eq!(resolve_bound(r.latest.as_ref(), Some(start), Some(end)), Some(end));
    // A window that starts later wins over the literal.
    let later = Utc.with_ymd_and_hms(2026, 11, 17, 18, 0, 0).unwrap();
    assert_eq!(resolve_bound(r.earliest.as_ref(), Some(later), Some(end)), Some(later));
    // Unbound, the range is not known.
    assert_eq!(resolve_bound(r.earliest.as_ref(), None, None), None);
}

/// NAN-5608 P2-18: "Open in Search" opens the response's range, so a
/// conversion whose range is not known is not exact.
#[test]
fn an_exact_conversion_needs_its_time_range() {
    let ctx = ocsf();
    let body = sql("SELECT id FROM ocsf_logs WHERE {W} AND class_uid = 1007");
    let bound = SqlToNplRequest {
        sql: body.clone(),
        window_start: Some(Utc.with_ymd_and_hms(2026, 11, 17, 0, 0, 0).unwrap()),
        window_end: Some(Utc.with_ymd_and_hms(2026, 11, 18, 0, 0, 0).unwrap()),
    };
    let r = convert_request(&bound, &ctx);
    assert!(r.exact && r.earliest.is_some() && r.latest.is_some(), "{r:?}");
    let unbound = SqlToNplRequest { sql: body, window_start: None, window_end: None };
    let r = convert_request(&unbound, &ctx);
    assert!(!r.exact, "{r:?}");
    assert!(r.differences.iter().any(|d| d.detail.contains("time range")), "{:?}", r.differences);
    // No lower bound in the SQL at all: Search would open on its default.
    let r = convert_request(
        &SqlToNplRequest { sql: "SELECT id FROM ocsf_logs WHERE class_uid = 1007".into(), window_start: None, window_end: None },
        &ctx,
    );
    assert!(!r.exact && r.differences.iter().any(|d| d.detail.contains("no lower bound")), "{r:?}");
}

// --- The independent review's findings (NAN-5630), one regression each ---

/// A condition function used as a value is refused, never an endless
/// eval/condition loop (a stack overflow aborts the process).
#[test]
fn condition_functions_as_values_are_refused_not_a_crash() {
    for body in [
        "SELECT positionCaseInsensitive(`process.cmd_line`, 'x') AS p FROM ocsf_logs WHERE {W} LIMIT 5",
        "SELECT id FROM ocsf_logs WHERE {W} AND position(`process.cmd_line`, 'a') > 0.5",
        "SELECT isNull(`process.name`, 1) AS p FROM ocsf_logs WHERE {W} LIMIT 5",
        "SELECT match(`process.name`, 'p', 1) AS p FROM ocsf_logs WHERE {W} LIMIT 5",
        "SELECT if(position(`process.name`, 'a'), 1, 0) AS p FROM ocsf_logs WHERE {W} LIMIT 5",
    ] {
        let r = convert_sql_to_npl(&sql(body), &ocsf());
        assert!(r.unsupported.is_some(), "{body}: {r:?}");
    }
}

/// lowerUTF8 folds non-ASCII letters, lower() does not: inside an aggregate
/// too.
#[test]
fn utf8_case_folding_is_never_ascii_folding() {
    let body = "SELECT `device.hostname`, max(lowerUTF8(`actor.user.name`)) AS u FROM ocsf_logs WHERE {W} GROUP BY `device.hostname`";
    let r = convert_sql_to_npl(&sql(body), &ocsf());
    assert!(!r.exact, "{r:?}");
    let d = compare_npl_with_sql(
        &sql(body),
        "* | eval _x1=lower(actor.user.name) | stats max(_x1) as u by device.hostname",
        &ocsf(),
    )
    .expect("compares");
    assert!(!d.is_empty());
}

/// `f(x) AS x` is applied once: the single eval is exact, a doubled one is not.
#[test]
fn a_self_referencing_alias_applies_once() {
    let body = "SELECT concat(source_type, '!') AS source_type FROM ocsf_logs WHERE {W} LIMIT 5";
    assert_eq!(exact(body), "* | eval source_type=concat(source_type, \"!\") | head 5 | table source_type");
    let d = compare_npl_with_sql(
        &sql(body),
        "* | eval source_type=concat(source_type, \"!\") | eval source_type=concat(source_type, \"!\") | head 5 | table source_type",
        &ocsf(),
    )
    .expect("compares");
    assert!(!d.is_empty(), "applied twice was called exact");
    // ClickHouse aliases do not depend on item order.
    let body = "SELECT length(h) AS l, `device.hostname` AS h FROM ocsf_logs WHERE {W} LIMIT 5";
    let d = compare_npl_with_sql(&sql(body), "* | eval l=len(h) | head 5 | table l, device.hostname", &ocsf()).expect("compares");
    assert!(!d.is_empty(), "a later alias was read as a column");
}

/// A stage after `stats` that drops or overwrites a group key changes the
/// result.
#[test]
fn dropping_or_overwriting_a_group_key_is_a_difference() {
    let body = "SELECT `device.hostname` AS host, count() AS n FROM ocsf_logs WHERE {W} GROUP BY host";
    for npl in [
        "* | stats count() as n by device.hostname | eval device.hostname=upper(device.hostname)",
        "* | stats count() as n by device.hostname | fields - device.hostname",
    ] {
        let d = compare_npl_with_sql(&sql(body), npl, &ocsf()).expect("compares");
        assert!(!d.is_empty(), "{npl} was called exact");
    }
}

/// `t.col` is the table's column even when a SELECT alias shares its name.
#[test]
fn a_qualified_column_is_not_the_alias_that_shadows_it() {
    let udm = ConvertContext::new(profile_for_id(SchemaId::Udm));
    let body = sql("SELECT length(command_line) AS dest_port, count() AS n FROM logs WHERE {W} AND logs.dest_port > 1000 GROUP BY dest_port");
    let r = convert_sql_to_npl(&body, &udm);
    assert!(!r.exact, "{r:?}");
    let d = compare_npl_with_sql(
        &body,
        "* | eval dest_port=len(command_line) | where dest_port>1000 | stats count() as n by dest_port",
        &udm,
    )
    .expect("compares");
    assert!(!d.is_empty());
}

/// Clauses that change the rows are a difference whoever wrote the nPL.
#[test]
fn row_changing_clauses_are_differences() {
    for (body, npl) in [
        (
            "SELECT toStartOfInterval(timestamp, INTERVAL 5 minute) AS b, count() AS n FROM ocsf_logs WHERE {W} GROUP BY b ORDER BY b WITH FILL STEP 300",
            "* | bin timestamp span=5m as b | stats count() as n by b | sort b",
        ),
        ("SELECT id FROM ocsf_logs WHERE {W} AND class_uid = 1007 ORDER BY id NULLS FIRST", "class_uid=1007 | sort id | table id"),
        ("SELECT id FROM ocsf_logs WHERE {W} AND class_uid = 1007 SETTINGS prefer_column_name_to_alias = 1", "class_uid=1007 | table id"),
        ("SELECT `process.name`, count() AS n FROM ocsf_logs WHERE {W} GROUP BY `process.name` QUALIFY n > 1", "* | stats count() as n by process.name"),
    ] {
        match compare_npl_with_sql(&sql(body), npl, &ocsf()) {
            Ok(d) => assert!(!d.is_empty(), "{body} was called exact"),
            Err(_) => {} // unreadable is never exact either
        }
    }
    // nPL that sets its own range.
    let d = compare_npl_with_sql(
        &sql("SELECT id FROM ocsf_logs WHERE {W} AND class_uid = 1007"),
        "earliest=-1h class_uid=1007 | table id",
        &ocsf(),
    )
    .expect("compares");
    assert!(d.iter().any(|d| d.detail.contains("earliest=")), "{d:?}");
}

/// A computed column does not make a plain `IN (SELECT …)` filter
/// unconvertible, and hidden names never take a SQL alias's name.
#[test]
fn subsearch_filters_and_hidden_names_survive_computed_columns() {
    let r = convert_sql_to_npl(
        &sql("SELECT lower(`process.name`) AS u, count() AS n FROM ocsf_logs WHERE {W} AND id IN (SELECT matched_log_id FROM {signals} WHERE {W}) GROUP BY u"),
        &ocsf(),
    );
    assert!(r.unsupported.is_none(), "{r:?}");
    let npl = exact(
        "SELECT `process.name`, count() AS _a1, countIf(status_id = 2) / count() AS r FROM ocsf_logs WHERE {W} GROUP BY `process.name`",
    );
    assert!(!npl.contains("fields - _a1"), "the user's own `_a1` was dropped: {npl}");
}

/// The AI path reads the window through a FROM subquery too.
#[test]
fn the_window_inside_a_from_subquery_is_the_window() {
    let (e, l) = time_bounds(&sql("SELECT * FROM (SELECT id, timestamp FROM ocsf_logs WHERE {W}) WHERE timestamp >= '2026-11-17 12:00:00'"), &ocsf());
    assert!(matches!(e, Some(TimeBound::Tightest { lower: true, .. })), "{e:?}");
    assert_eq!(l, Some(TimeBound::WindowEnd));
}
