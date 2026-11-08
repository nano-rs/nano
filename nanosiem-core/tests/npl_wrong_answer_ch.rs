// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4902 P0-4: nPL -> SQL silent-wrong-answer differential suite.
//!
//! Every case generates SQL with the production generator on BOTH the UDM
//! (`logs`) and OCSF (`ocsf_logs`) profiles, runs it on a disposable
//! ClickHouse carrying the checked-in DDL, and compares the rows with the
//! fixture truth (see `npl_wrong_answer_ch/harness.rs`). Each defect was first
//! reproduced on `clickhouse/dev` with this harness before its fix was ported.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:8123 NANOSIEM_TEST_CLICKHOUSE_USER=default \
//!   cargo test -p nanosiem-core --test npl_wrong_answer_ch
//! ```
//! Without `NANOSIEM_TEST_CLICKHOUSE_URL` every test returns early.
#[path = "npl_wrong_answer_ch/harness.rs"]
mod harness;
use chrono::Duration;
use harness::*;
use nanosiem_core::query::TimeRange;

/// NAN-4280: the window is half-open `[start, end)`. The inclusive BETWEEN
/// counted the event exactly on `end` (dave, minute 60), so two adjacent
/// windows double-counted a boundary event (carol, minute 30).
#[tokio::test]
async fn nan4280_time_window_is_half_open() {
    let Some(ch) = Ch::connect("nan4280").await else { return };
    for p in BOTH {
        assert_eq!(column(&ch.rows(p, "* | stats count").await, "count"), ["5"], "{p:?}");
        let half = |from: i64, to: i64| TimeRange { start: t0() + Duration::minutes(from), end: t0() + Duration::minutes(to) };
        let first = ch.run(p, "* | stats count", &half(0, 30)).await.unwrap();
        let second = ch.run(p, "* | stats count", &half(30, 60)).await.unwrap();
        assert_eq!((s(&first[0], "count"), s(&second[0], "count")), ("3".into(), "2".into()), "{p:?}");
        let users = column(&ch.run(p, &npl(p, "* | table {user}"), &half(30, 60)).await.unwrap(), f(p, "user"));
        assert!(users.contains(&"carol".to_string()) && !users.contains(&"dave".to_string()), "{p:?}: {users:?}");
    }
    ch.drop().await;
}

/// NAN-4214: `head N` without a sort cuts the NEWEST N events, also behind
/// `where` / `eval` and ahead of `table` / `fields` (it took the oldest rows
/// the reader produced first).
#[tokio::test]
async fn nan4214_head_without_sort_returns_the_newest_events() {
    let Some(ch) = Ch::connect("nan4214").await else { return };
    for p in BOTH {
        for q in [
            "* | where {bytes_in} > 0 | head 2 | table {user}",
            "* | eval x=1 | head 2 | table {user}",
            "* | table {user} | head 2",
            "* | fields {user} | head 2",
            "* | where {bytes_in} > 0 | head 2",
        ] {
            let q = npl(p, q);
            assert_eq!(column(&ch.rows(p, &q).await, f(p, "user")), ["bob", "carol"], "{p:?} `{q}`");
        }
    }
    ch.drop().await;
}

/// NAN-4278: `tail N` is the end of the CURRENT order, listed from the end
/// (default newest-first order -> the oldest N, oldest first; after a sort ->
/// the sort's last N). It returned the newest N and ignored a prior sort.
/// An explicit `sort -x | head N` keeps the sort's order instead of being
/// re-sorted newest-first.
#[tokio::test]
async fn nan4278_tail_and_explicit_sort_keep_the_current_order() {
    let Some(ch) = Ch::connect("nan4278").await else { return };
    for p in BOTH {
        let users = |rows: Vec<serde_json::Value>| column(&rows, f(p, "user"));
        assert_eq!(users(ch.rows(p, &npl(p, "* | tail 2 | table {user}")).await), ["erin", "Alice"], "{p:?}");
        assert_eq!(users(ch.rows(p, &npl(p, "* | tail 2")).await), ["erin", "Alice"], "{p:?}");
        assert_eq!(users(ch.rows(p, &npl(p, "* | sort {user} | tail 2 | table {user}")).await), ["erin", "carol"], "{p:?}");
        assert_eq!(users(ch.rows(p, &npl(p, "* | reverse | head 2 | table {user}")).await), ["erin", "Alice"], "{p:?}");
        for q in ["* | sort -{bytes_in} | head 3", "* | sort -{bytes_in} | where {bytes_in} > 0 | head 3"] {
            let rows = ch.rows(p, &npl(p, q)).await;
            assert_eq!(column(&rows, f(p, "bytes_in")), ["900", "300", "200"], "{p:?} `{q}`");
        }
    }
    ch.drop().await;
}

/// NAN-4276: a number against a String column. `| where status=7` / `!=` /
/// `IN` compare the text the number was written as, a range compares the
/// numeric value (both were "no supertype for String, UInt8"), the
/// search-term range is numeric instead of lexicographic ('500' > '1000'),
/// a stats by-field passing the String column through keeps the text
/// typing, and `==` is equality.
#[tokio::test]
async fn nan4276_numbers_against_string_columns_and_double_equals() {
    let Some(ch) = Ch::connect("nan4276").await else { return };
    for p in BOTH {
        let users = |rows: Vec<serde_json::Value>| column(&rows, f(p, "user"));
        let count = |rows: Vec<serde_json::Value>| column(&rows, "count");
        assert_eq!(users(ch.rows(p, &npl(p, "* | where {status} = 7 | table {user}")).await), ["bob"], "{p:?}");
        assert_eq!(count(ch.rows(p, &npl(p, "* | where {status} != 7 | stats count")).await), ["4"], "{p:?}");
        assert_eq!(users(ch.rows(p, &npl(p, "* | where {status} > 1000 | table {user}")).await), ["carol"], "{p:?}");
        assert_eq!(users(ch.rows(p, &npl(p, "{status}>1000 | table {user}")).await), ["carol"], "{p:?}");
        assert_eq!(count(ch.rows(p, &npl(p, "{status}>=500 | stats count")).await), ["2"], "{p:?}");
        assert_eq!(count(ch.rows(p, &npl(p, "* | stats count by {status} | where {status}=7")).await), ["1"], "{p:?}");
        assert_eq!(count(ch.rows(p, &npl(p, "* | eval s=lower({status}) | where s=7 | stats count")).await), ["1"], "{p:?}");
        assert_eq!(count(ch.rows(p, &npl(p, "* | where {user}==\"bob\" | stats count")).await), ["2"], "{p:?}");
        assert_eq!(count(ch.rows(p, &npl(p, "{user}==\"bob\" | stats count")).await), ["2"], "{p:?}");
        // Numeric columns and aggregate outputs keep the numeric compare.
        assert_eq!(count(ch.rows(p, &npl(p, "* | where {dest_port} > 100 | stats count")).await), ["2"], "{p:?}");
        assert_eq!(count(ch.rows(p, "* | stats count | where count > 3").await), ["5"], "{p:?}");
    }
    ch.drop().await;
}

/// NAN-4279: earliest()/latest() are the value on the chronologically first /
/// last event (they were min/max of the value); un-aliased aggregates sharing
/// a function get unique SPL-style names (`stats dc(a), dc(b)` was
/// MULTIPLE_EXPRESSIONS_FOR_ALIAS); percN accepts any N (perc99 was a parse
/// error); dedup keeps the first row in newest-first order (it kept the
/// oldest) and keepfirst=false keeps the oldest.
#[tokio::test]
async fn nan4279_earliest_latest_unique_names_percn_dedup_order() {
    let Some(ch) = Ch::connect("nan4279").await else { return };
    for p in BOTH {
        let rows = ch.rows(p, &npl(p, "* | stats earliest({user}) as e, latest({user}) as l")).await;
        assert_eq!((s(&rows[0], "e"), s(&rows[0], "l")), ("erin".into(), "bob".into()), "{p:?}");
        let rows = ch.rows(p, &npl(p, "* | stats earliest({user}) as e, latest({user}) as l by {host} | where {host}=\"ws-1\"")).await;
        assert_eq!((s(&rows[0], "e"), s(&rows[0], "l")), ("Alice".into(), "carol".into()), "{p:?}");
        let rows = ch.rows(p, &npl(p, "* | eventstats latest({user}) as l | table l | head 1")).await;
        assert_eq!(column(&rows, "l"), ["bob"], "{p:?}");
        let rows = ch.rows(p, &npl(p, "* | stats dc({user}), dc({host})")).await;
        assert_eq!(s(&rows[0], &npl(p, "dc({user})")), "4", "{p:?}: {rows:?}");
        assert_eq!(s(&rows[0], &npl(p, "dc({host})")), "3", "{p:?}: {rows:?}");
        let rows = ch.rows(p, &npl(p, "* | stats perc99({bytes_in}) as p99")).await;
        assert_eq!(rows.len(), 1, "{p:?}");
        let newest = ch.rows(p, &npl(p, "* | dedup {host} | where {host}=\"ws-1\" | table {user}")).await;
        assert_eq!(column(&newest, f(p, "user")), ["carol"], "{p:?}");
        let oldest = ch.rows(p, &npl(p, "* | dedup {host} keepfirst=false | where {host}=\"ws-1\" | table {user}")).await;
        assert_eq!(column(&oldest, f(p, "user")), ["Alice"], "{p:?}");
    }
    ch.drop().await;
}

/// NAN-4285: CIDR literals in `IN` / `NOT IN` (search term and `| where`)
/// and in a `| where ip=cidr` are network membership. The list form compiled
/// to a string IN-list, so `IN` matched nothing and `NOT IN` everything.
#[tokio::test]
async fn nan4285_cidr_literals_in_lists_are_network_membership() {
    let Some(ch) = Ch::connect("nan4285").await else { return };
    for p in BOTH {
        let count = |rows: Vec<serde_json::Value>| column(&rows, "count");
        for (q, want) in [
            // dest_ip: 10.0.0.7, 10.0.0.5, 203.0.113.9, 172.16.5.5, 198.51.100.1
            ("{dest_ip} IN (10.0.0.0/8, 172.16.0.0/12) | stats count", "3"),
            ("{dest_ip} NOT IN (10.0.0.0/8, 172.16.0.0/12) | stats count", "2"),
            ("{dest_ip} IN (10.0.0.0/8, 203.0.113.9) | stats count", "3"),
            ("* | where {dest_ip} IN (10.0.0.0/8) | stats count", "2"),
            ("* | where {dest_ip} NOT IN (10.0.0.0/8, 192.168.0.0/16) | stats count", "3"),
            ("* | where {dest_ip}=10.0.0.0/8 | stats count", "2"),
            ("* | where {dest_ip}!=10.0.0.0/8 | stats count", "3"),
            ("{dest_ip}=10.0.0.0/8 | stats count", "2"),
            ("{dest_ip}!=10.0.0.0/8 | stats count", "3"),
        ] {
            assert_eq!(count(ch.rows(p, &npl(p, q)).await), [want], "{p:?} `{q}`");
        }
    }
    ch.drop().await;
}

/// NAN-4289: AND / OR chains compile flat. 400 pasted `NOT user=xN` terms
/// nested one parenthesis level per term and exceeded ClickHouse's max parse
/// depth (Code 306), in the search and in `| where`.
#[tokio::test]
async fn nan4289_long_and_chains_compile_flat() {
    let Some(ch) = Ch::connect("nan4289").await else { return };
    let terms = |sep: &str| (0..400).map(|i| format!("NOT {{user}}=x{i}")).collect::<Vec<_>>().join(sep);
    let ors = (0..400).map(|i| format!("{{user}}=x{i}")).collect::<Vec<_>>().join(" OR ");
    for p in BOTH {
        for (q, want) in [
            (format!("{} | stats count", terms(" ")), "5"),
            (format!("* | where {} | stats count", terms(" AND ")), "5"),
            (format!("({ors} OR {{user}}=bob) | stats count"), "2"),
            (format!("* | where {ors} OR {{user}}=\"bob\" | stats count"), "2"),
        ] {
            let q = npl(p, &q);
            assert_eq!(column(&ch.rows(p, &q).await, "count"), [want], "{p:?} `{}…`", &q[..60]);
        }
    }
    ch.drop().await;
}

/// NAN-4303: `+` with a string operand concatenates (it cast both sides to
/// Float64: Code 43 "Illegal types Float64 and String"); number + number and
/// untyped stage aliases keep the numeric add.
#[tokio::test]
async fn nan4303_plus_with_a_string_operand_concatenates() {
    let Some(ch) = Ch::connect("nan4303").await else { return };
    for p in BOTH {
        for (q, want) in [
            ("* | eval x={user}+\"_s\" | table x | head 1", "bob_s"),
            ("* | eval x=\"a\"+\"b\" | table x | head 1", "ab"),
            ("* | eval x=\"port \"+{dest_port} | table x | head 1", "port 53"),
            ("* | eval x=lower({user})+\"@corp\" | table x | head 1", "bob@corp"),
            ("* | eval x={dest_port}+1 | table x | head 1", "54"),
            ("* | stats sum({bytes_in}) as a, count as b | eval x=a+b | table x", "1555"),
        ] {
            assert_eq!(column(&ch.rows(p, &npl(p, q)).await, "x"), [want], "{p:?} `{q}`");
        }
    }
    ch.drop().await;
}

/// NAN-4284: a join narrows its subsearch to the main side's keys BEFORE the
/// `maxout` cap (it capped first, so the main side's keys mostly fell outside
/// the arbitrary capped rows), an unmatched left-join row reads NULL (not the
/// type default 0), and `time_diff(t1, t2)` is the seconds from t2 to t1.
#[tokio::test]
async fn nan4284_capped_join_narrows_first_and_time_diff() {
    let Some(ch) = Ch::connect("nan4284").await else { return };
    for p in BOTH {
        let q = npl(p, "{user}=carol | join type=left maxout=1 {user} [search * | stats count as n by {user}] | table {user}, n");
        assert_eq!(column(&ch.rows(p, &q).await, "n"), ["1"], "{p:?} `{q}`");
        let q = npl(p, "{user}=carol | join maxout=1 {user} [search * | stats count as n by {user}] | stats count");
        assert_eq!(column(&ch.rows(p, &q).await, "count"), ["1"], "{p:?} `{q}`");
        let q = npl(p, "{user}=carol OR {user}=erin | join type=left {user} [search {user}=erin | stats count as n by {user}] | sort {user} | table {user}, n");
        assert_eq!(column(&ch.rows(p, &q).await, "n"), ["null", "1"], "{p:?} `{q}`");
        // t1 later than t2 is positive.
        let q = "* | eval d=time_diff(now(), _time) | where d > 0 | stats count";
        assert_eq!(column(&ch.rows(p, q).await, "count"), ["5"], "{p:?} `{q}`");
        assert_eq!(column(&ch.rows(p, "* | eval d=time_diff(_time, _time) | table d | head 1").await, "d"), ["0"], "{p:?}");
    }
    ch.drop().await;
}

/// NAN-4291: an ungrouped stats over no rows is one row with count/dc 0 and
/// every other aggregate NULL. ClickHouse gave each its type default
/// (`max(_time)` 1970-01-01, `max`/`sum` 0, `values` ''). Grouped stats over
/// no rows stay empty; non-empty windows are unchanged.
#[tokio::test]
async fn nan4291_ungrouped_stats_over_no_rows_is_count_zero_and_nulls() {
    let Some(ch) = Ch::connect("nan4291").await else { return };
    for p in BOTH {
        let q = npl(p, "{user}=nobody | stats count, dc({user}) as d, max({bytes_in}) as m, sum({bytes_in}) as su, min({bytes_in}) as mi, values({user}) as v, max(_time) as t, earliest({user}) as e");
        let rows = ch.rows(p, &q).await;
        assert_eq!(rows.len(), 1, "{p:?}");
        for (key, want) in [("count", "0"), ("d", "0"), ("m", "null"), ("su", "null"), ("mi", "null"), ("v", "null"), ("t", "null"), ("e", "null")] {
            assert_eq!(s(&rows[0], key), want, "{p:?} {key}: {rows:?}");
        }
        assert!(ch.rows(p, &npl(p, "{user}=nobody | stats count by {host}")).await.is_empty(), "{p:?}");
        let rows = ch.rows(p, &npl(p, "* | stats count, max({bytes_in}) as m, sum({bytes_in}) as su")).await;
        assert_eq!((s(&rows[0], "count"), s(&rows[0], "m"), s(&rows[0], "su")), ("5".into(), "900".into(), "1550".into()), "{p:?}");
    }
    ch.drop().await;
}

/// NAN-4295: `stats … by <array column>` groups by EACH element (it grouped
/// by the whole array: keys like `['SeDebugPrivilege','T1110']`, and an empty
/// array formed its own group).
#[tokio::test]
async fn nan4295_stats_by_an_array_groups_by_each_element() {
    let Some(ch) = Ch::connect("nan4295").await else { return };
    for p in BOTH {
        let lower = |rows: &[serde_json::Value], key: &str| {
            let mut out: Vec<String> = rows.iter().map(|r| format!("{}={}", s(r, key).to_lowercase(), s(r, "count"))).collect();
            out.sort();
            out
        };
        let rows = ch.rows(p, &npl(p, "* | stats count by {tags}")).await;
        assert_eq!(lower(&rows, f(p, "tags")), ["sedebugprivilege=1", "seimpersonateprivilege=1", "t1110=2"], "{p:?}");
        let rows = ch.rows(p, &npl(p, "* | where {bytes_in} > 150 | stats count by {tags}, {host}")).await;
        assert_eq!(lower(&rows, f(p, "tags")), ["sedebugprivilege=1", "t1110=1", "t1110=1"], "{p:?}: {rows:?}");
        let rows = ch.rows(p, &npl(p, "* | stats dc({user}) as u by {tags} | where u > 1")).await;
        assert_eq!(column(&rows, f(p, "tags")).iter().map(|t| t.to_lowercase()).collect::<Vec<_>>(), ["t1110"], "{p:?}");
    }
    ch.drop().await;
}

/// NAN-4283: array-field equality is any-element and case-insensitive on
/// both profiles, in the search and in `| where` (UDM `| where tags="x"` was
/// an ILLEGAL_TYPE_OF_ARGUMENT error: `lower()` of an Array); an unquoted URL
/// value is never a comment.
#[tokio::test]
async fn nan4283_array_equality_any_element_and_url_values() {
    let Some(ch) = Ch::connect("nan4283").await else { return };
    for p in BOTH {
        for (q, want) in [
            ("{tags}=\"t1110\" | stats count", "2"),
            ("{tags}=T1110 | stats count", "2"),
            ("* | where {tags}=\"T1110\" | stats count", "2"),
            ("* | where {tags}!=\"t1110\" | stats count", "3"),
            ("{message}=*https://host/x | stats count", "1"),
        ] {
            assert_eq!(column(&ch.rows(p, &npl(p, q)).await, "count"), [want], "{p:?} `{q}`");
        }
    }
    ch.drop().await;
}

/// NAN-4288: `prevalence prevalence_file_hash < 5` (the nPL reference's own
/// example, and the parser's own error hint) parses as the hash-rarity filter
/// it names; it was "needs a comparison against a host count". Parse-only:
/// the prevalence stage runs against the prevalence service, not this table.
#[test]
fn nan4288_prevalence_filter_accepts_the_column_names() {
    use nanosiem_core::query::parse_query;
    for (column_form, filter_form) in [
        ("* | prevalence prevalence_file_hash < 5", "* | prevalence hash_prevalence < 5"),
        ("* | prevalence prevalence_process_hash <= 3", "* | prevalence hash_prevalence <= 3"),
        ("* | prevalence prevalence_dest_domain < 10", "* | prevalence domain_prevalence < 10"),
    ] {
        assert_eq!(
            parse_query(column_form).unwrap_or_else(|e| panic!("`{column_form}`: {e}")),
            parse_query(filter_form).unwrap(),
            "{column_form}"
        );
    }
}

/// NAN-4278 review: `tail` / `reverse` after a projection or a row-preserving
/// stage take the end of the explicit order deterministically. 40 events in
/// 5 unmerged parts, read with max_threads=16, 20 runs each: the result must
/// be the exact end of the sort every time (it numbered the rows of an
/// unordered CTE, or dropped the sort after `eval`).
#[tokio::test]
async fn nan4278_tail_after_projection_and_eval_is_deterministic() {
    let Some(ch) = Ch::connect("nan4278det").await else { return };
    let start = t0() + Duration::hours(2);
    let w2 = TimeRange { start, end: start + Duration::hours(1) };
    // bytes_in is a shuffled permutation of 1..=40 (37 is coprime to 41).
    let bytes = |i: u64| (i * 37) % 41;
    for p in BOTH {
        let table = match p { Profile::Udm => "logs", Profile::Ocsf => "ocsf_logs" };
        ch.exec(&format!("SYSTEM STOP MERGES {}.{table}", ch.db)).await;
        for part in 0..5u64 {
            let rows: Vec<String> = (1..=8u64)
                .map(|k| {
                    let i = part * 8 + k;
                    let ts = (start + Duration::seconds(i as i64 * 60)).format("%Y-%m-%d %H:%M:%S%.3f").to_string();
                    let mut row = serde_json::json!({"timestamp": ts, "source_type": "fixture"});
                    row[f(p, "user")] = format!("u{i:02}").into();
                    row[f(p, "bytes_in")] = bytes(i).into();
                    if p == Profile::Ocsf {
                        row["metadata.uid"] = format!("w2-{i:02}").into();
                    }
                    row.to_string()
                })
                .collect();
            ch.insert(p, &rows).await;
        }
        // The five largest byte counts, listed from the end of the ascending sort.
        let mut by_bytes: Vec<u64> = (1..=40).collect();
        by_bytes.sort_by_key(|&i| bytes(i));
        let last5: Vec<String> = by_bytes.iter().rev().take(5).map(|i| format!("u{i:02}")).collect();
        let first5: Vec<String> = by_bytes.iter().take(5).map(|i| format!("u{i:02}")).collect();
        let oldest3: Vec<String> = ["u01", "u02", "u03"].iter().map(|s| s.to_string()).collect();
        for (q, want) in [
            ("* | sort {bytes_in} | table {user} | tail 5", &last5),
            ("* | sort {bytes_in} | eval x=1 | tail 5", &last5),
            ("* | sort {bytes_in} | eval x=1 | tail 5 | table {user}", &last5),
            ("* | sort {bytes_in} | table {user}, {bytes_in} | eval y=1 | tail 5", &last5),
            // NAN-4933: rename MOVES the field (sequential, as Nano-side).
            ("* | sort {bytes_in} | rename {user} as who | eval {user}=who | tail 5", &last5),
            ("* | table {user} | tail 3", &oldest3),
            ("* | sort -{bytes_in} | fields {user} | reverse | head 5", &first5),
        ] {
            let q = npl(p, q);
            for run in 0..20 {
                let rows = ch.run(p, &q, &w2).await.unwrap_or_else(|e| panic!("{p:?} `{q}`: {e}"));
                assert_eq!(&column(&rows, f(p, "user")), want, "{p:?} `{q}` run {run}");
            }
        }
        // An order a reshaping stage destroyed has no deterministic end.
        let err = ch.run(p, &npl(p, "* | sort {bytes_in} | dedup {user} | tail 2"), &w2).await.unwrap_err();
        assert!(err.contains("tail/reverse"), "{p:?}: {err}");
    }
    ch.drop().await;
}

/// NAN-4276 review: an eval of `<String> + <number>` is text (it compiles to
/// `concat`), so a later numeric-literal compare types the literal as text
/// instead of failing with "no supertype for String, UInt8".
#[tokio::test]
async fn nan4276_string_plus_eval_output_compares_as_text() {
    let Some(ch) = Ch::connect("nan4276plus").await else { return };
    for p in BOTH {
        // status "7" + 1 -> "71" (bob).
        let rows = ch.rows(p, &npl(p, "* | eval code={status}+1 | where code=71 | table {user}")).await;
        assert_eq!(column(&rows, f(p, "user")), ["bob"], "{p:?}");
        let rows = ch.rows(p, &npl(p, "* | eval code={status}+1 | where code!=71 | stats count")).await;
        assert_eq!(column(&rows, "count"), ["4"], "{p:?}");
    }
    ch.drop().await;
}

/// NAN-4284 review: the join narrowing set is bounded. Past
/// JOIN_NARROW_KEY_BOUND distinct main-side keys the narrowing switches off
/// and the join keeps the plain cap (it no longer builds an unbounded set);
/// the query still answers every main row.
#[tokio::test]
async fn nan4284_join_narrowing_falls_back_past_the_key_bound() {
    let Some(ch) = Ch::connect("nan4284bound").await else { return };
    let start = t0() + Duration::hours(5);
    let w = TimeRange { start, end: start + Duration::hours(1) };
    let n = 100_050u64;
    for p in BOTH {
        let table = match p { Profile::Udm => "logs", Profile::Ocsf => "ocsf_logs" };
        let user = f(p, "user");
        ch.exec(&format!(
            "INSERT INTO {db}.{table} (timestamp, source_type, `{user}`) SELECT toDateTime64('{ts}', 3, 'UTC') + toIntervalMillisecond(number), 'fixture', concat('k', toString(number)) FROM numbers({n})",
            db = ch.db,
            ts = start.format("%Y-%m-%d %H:%M:%S"),
        ))
        .await;
        let q = npl(p, "* | join type=left maxout=10 {user} [search * | stats count as c by {user}] | stats count as rows, count(c) as matched");
        let rows = ch.run(p, &q, &w).await.unwrap_or_else(|e| panic!("{p:?}: {e}"));
        assert_eq!(s(&rows[0], "rows"), n.to_string(), "{p:?}: {rows:?}");
        let matched: u64 = s(&rows[0], "matched").parse().unwrap();
        assert!(matched <= 10, "{p:?}: the cap still bounds the fallback: {rows:?}");
        // Under the bound the narrowing still applies (one key, cap 1).
        let q = npl(p, "{user}=k77 | join type=left maxout=1 {user} [search * | stats count as c by {user}] | table c");
        assert_eq!(column(&ch.run(p, &q, &w).await.unwrap(), "c"), ["1"], "{p:?}");
    }
    ch.drop().await;
}

/// NAN-4284 merge-captain repro: a left join whose subsearch returns a column
/// the main side also carries (`fields host, src_ip`) must yield ONE column
/// per name. With `join_use_nulls=1` the sub column became Nullable(String)
/// next to main's String of the same name and ClickHouse failed with Code 352
/// on the OCSF store.
#[tokio::test]
async fn nan4284_join_with_a_clashing_subsearch_column() {
    let Some(ch) = Ch::connect("nan4284clash").await else { return };
    for p in BOTH {
        // Sub: only bob's rows (ws-2); every ws-2 main row matches, others miss.
        let q = npl(p, "* | join type=left {host} [search {user}=bob | fields {host}, {src_ip}] | sort {user} | table {user}, {host}, {src_ip}");
        let rows = ch.rows(p, &q).await;
        assert_eq!(rows.len(), 5, "{p:?}: {rows:?}");
        let ws2: Vec<_> = rows.iter().filter(|r| s(r, f(p, "host")) == "ws-2").collect();
        assert_eq!(ws2.len(), 2, "{p:?}: {rows:?}");
        for r in &ws2 {
            let ip = s(r, f(p, "src_ip"));
            assert!(ip == "8.8.8.8" || ip == "8.8.4.4", "{p:?}: {r}");
        }
        // A miss keeps the main side's own value of the shared column.
        let alice = rows.iter().find(|r| s(r, f(p, "user")) == "Alice").unwrap();
        assert_eq!(s(alice, f(p, "src_ip")), "10.1.2.3", "{p:?}: {alice}");
        // Inner join over the same shape.
        let q = npl(p, "* | join {host} [search {user}=bob | fields {host}, {src_ip}] | stats count");
        assert_eq!(column(&ch.rows(p, &q).await, "count"), ["2"], "{p:?}");
    }
    ch.drop().await;
}

/// The merge captain's OCSF query verbatim: Process Activity left-joined to
/// Authentication by host, the subsearch returning `src_endpoint.ip` that the
/// main rows also carry. It failed with ClickHouse Code 352 under
/// `join_use_nulls=1`; the UDM equivalent joins `src_host` / `src_ip`.
#[tokio::test]
async fn nan4284_ocsf_process_to_auth_join_on_the_ocsf_store() {
    let Some(ch) = Ch::connect("nan4284ocsf").await else { return };
    let start = t0() + Duration::hours(7);
    let w = TimeRange { start, end: start + Duration::hours(1) };
    let at = |m: i64| (start + Duration::minutes(m)).format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let ocsf = [
        serde_json::json!({"timestamp": at(1), "source_type": "fixture", "class_uid": 1007, "metadata.uid": "p1", "device.hostname": "ws-a", "src_endpoint.ip": "", "process.name": "cmd.exe"}),
        serde_json::json!({"timestamp": at(2), "source_type": "fixture", "class_uid": 1007, "metadata.uid": "p2", "device.hostname": "ws-b", "src_endpoint.ip": "", "process.name": "powershell.exe"}),
        serde_json::json!({"timestamp": at(3), "source_type": "fixture", "class_uid": 3002, "metadata.uid": "a1", "device.hostname": "ws-a", "src_endpoint.ip": "10.7.7.7", "actor.user.name": "alice"}),
    ];
    ch.insert(Profile::Ocsf, &ocsf.iter().map(|r| r.to_string()).collect::<Vec<_>>()).await;
    let q = "class_uid=1007 | join type=left device.hostname [search class_uid=3002 | fields device.hostname, src_endpoint.ip] | sort device.hostname | table device.hostname, process.name, src_endpoint.ip";
    let rows = ch.run(Profile::Ocsf, q, &w).await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(column(&rows, "device.hostname"), ["ws-a", "ws-b"], "{rows:?}");
    assert_eq!(column(&rows, "src_endpoint.ip"), ["10.7.7.7", ""], "{rows:?}");
    // UDM equivalent.
    let udm = [
        serde_json::json!({"timestamp": at(1), "source_type": "proc", "src_host": "ws-a", "src_ip": "", "process_name": "cmd.exe"}),
        serde_json::json!({"timestamp": at(2), "source_type": "proc", "src_host": "ws-b", "src_ip": "", "process_name": "powershell.exe"}),
        serde_json::json!({"timestamp": at(3), "source_type": "auth", "src_host": "ws-a", "src_ip": "10.7.7.7", "user": "alice"}),
    ];
    ch.insert(Profile::Udm, &udm.iter().map(|r| r.to_string()).collect::<Vec<_>>()).await;
    let q = "source_type=proc | join type=left src_host [search source_type=auth | fields src_host, src_ip] | sort src_host | table src_host, process_name, src_ip";
    let rows = ch.run(Profile::Udm, q, &w).await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(column(&rows, "src_ip"), ["10.7.7.7", ""], "{rows:?}");
    // overwrite=false keeps the main side's own value.
    let q = "source_type=proc | join type=left overwrite=false src_host [search source_type=auth | fields src_host, src_ip] | sort src_host | table src_host, src_ip";
    let rows = ch.run(Profile::Udm, q, &w).await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(column(&rows, "src_ip"), ["", ""], "{rows:?}");
    ch.drop().await;
}
