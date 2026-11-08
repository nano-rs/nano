// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4933 (lane L11): nPL batch B/C defects from origin/main, each reproduced
//! on clickhouse/dev against ClickHouse 26.10 with the checked-in `logs` (UDM)
//! and `ocsf_logs` (OCSF) DDL before its fix was ported. Same disposable
//! harness as `npl_wrong_answer_ch` (NAN-4902 P0-4).
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:8123 NANOSIEM_TEST_CLICKHOUSE_USER=default \
//!   cargo test -p nanosiem-core --test npl_bc_ch
//! ```
//! Without `NANOSIEM_TEST_CLICKHOUSE_URL` every test returns early.
#[path = "npl_wrong_answer_ch/harness.rs"]
mod harness;
use harness::*;

/// One `stats` / `table` cell as text.
async fn cell(ch: &Ch, p: Profile, q: &str, key: &str) -> String {
    let q = npl(p, q);
    let rows = ch.rows(p, &q).await;
    assert_eq!(rows.len(), 1, "{p:?} `{q}`: {rows:?}");
    s(&rows[0], key)
}

/// An OCSF event whose body is only in `raw_data` (a Tenzir-shaped producer).
async fn add_raw_data_only_event(ch: &Ch) {
    ch.insert(
        Profile::Ocsf,
        &[r#"{"timestamp":"2026-10-01 00:50:00.000","source_type":"fixture","class_uid":4001,"metadata.uid":"uid-raw","raw_data":"xx rawonly yy"}"#.to_string()],
    )
    .await;
}

/// NAN-3034: a bare `*kw*` is a wildcard keyword over EVERY body column. It
/// parsed to `message=/(?i)kw/`, so an OCSF event whose body is only in
/// `raw_data` was missed (dev: `*rawonly*` 0 rows, `rawonly` 1 row).
#[tokio::test]
async fn nan3034_double_sided_wildcard_keyword_searches_raw_data() {
    let Some(ch) = Ch::connect("nan3034").await else { return };
    add_raw_data_only_event(&ch).await;
    assert_eq!(cell(&ch, Profile::Ocsf, "*rawonly* | stats count", "count").await, "1");
    assert_eq!(cell(&ch, Profile::Ocsf, "rawonly | stats count", "count").await, "1");
    // An explicit field still searches only that field.
    assert_eq!(cell(&ch, Profile::Ocsf, "message=*rawonly* | stats count", "count").await, "0");
    for p in BOTH {
        assert_eq!(cell(&ch, p, "*System32* | stats count", "count").await, "1", "{p:?}");
    }
    ch.drop().await;
}

/// NAN-3041: a bare keyword with `*`/`?` matches TERMS. `cmd*` compiled to a
/// whole-body `iLike 'cmd%'` and matched nothing (dev: 0 rows) although the
/// body `C:\Windows\System32\cmd.exe` has the term `cmd.exe`.
#[tokio::test]
async fn nan3041_term_prefix_keywords_match_words_inside_the_body() {
    let Some(ch) = Ch::connect("nan3041kw").await else { return };
    for p in BOTH {
        for (q, want) in [
            ("cmd* | stats count", "1"),
            ("System32* | stats count", "1"),
            ("*.exe | stats count", "1"),
            ("c?d.exe | stats count", "1"),
            // A prefix that is only inside a word is not a term start.
            ("md* | stats count", "0"),
        ] {
            assert_eq!(cell(&ch, p, q, "count").await, want, "{p:?} `{q}`");
        }
    }
    ch.drop().await;
}

/// NAN-3041: eval / if() predicates mean what they mean in `| where`.
/// On dev CONTAINS and LIKE were case-sensitive, `f=/re/` compared the field
/// to the pattern text, `f="x"` was case-sensitive (all 0 where `where` finds
/// Alice), and `IN (...)` / `in()` did not parse or compile.
#[tokio::test]
async fn nan3041_eval_predicates_match_where() {
    let Some(ch) = Ch::connect("nan3041eval").await else { return };
    for p in BOTH {
        for (pred, want) in [
            (r#"{user} CONTAINS "ALI""#, "1"),
            (r#"{user} LIKE "ALI%""#, "1"),
            (r#"like({user}, "ALI%")"#, "1"),
            (r#"{user}=/^ali/"#, "1"),
            (r#"{user}="alice""#, "1"),
            (r#"{user}!="alice""#, "4"),
            (r#"{user} IN ("alice", "BOB")"#, "3"),
            (r#"{user} NOT IN ("alice", "BOB")"#, "2"),
            (r#"in({user}, "alice")"#, "1"),
            (r#"in({dest_port}, 80, 53)"#, "2"),
            // match() stays the explicit case-sensitive regex.
            (r#"match({user}, "^ali")"#, "0"),
        ] {
            let q = format!("* | eval m=if({pred}, 1, 0) | stats sum(m) as s");
            assert_eq!(cell(&ch, p, &q, "s").await, want, "{p:?} eval `{pred}`");
        }
        assert_eq!(cell(&ch, p, r#"* | where in({user}, "BOB") | stats count"#, "count").await, "2", "{p:?}");
        assert_eq!(cell(&ch, p, r#"* | where like({user}, "ali%") | stats count"#, "count").await, "1", "{p:?}");
    }
    ch.drop().await;
}


/// NAN-3055: IP predicates are false (not a query error) on a non-IP value,
/// ipv4_to_int of junk is 0, and strftime `%M` is minutes. On dev
/// `is_private_ip(<user>)` failed the search with CANNOT_PARSE_TEXT, ipv4_to_int
/// with CANNOT_PARSE_IPV4, and `%M` rendered `October`.
#[tokio::test]
async fn nan3055_ip_functions_on_non_ip_values_and_strftime_minutes() {
    let Some(ch) = Ch::connect("nan3055fn").await else { return };
    for p in BOTH {
        let q = "* | eval a=is_private_ip({user}), b=is_public_ip({user}), c=is_loopback({message}), \
                 d=cidr_match(\"10.0.0.0/8\", {user}), e=cidr_match({user}, \"10.0.0.0/8\", \"8.8.0.0/16\"), \
                 f=ipv4_to_int({user}), g=is_private_ip({src_ip}) \
                 | stats sum(a) as a, sum(b) as b, sum(c) as c, sum(d) as d, sum(e) as e, sum(f) as f, sum(g) as g";
        let rows = ch.rows(p, &npl(p, q)).await;
        let got: Vec<String> = ["a", "b", "c", "d", "e", "f", "g"].iter().map(|k| s(&rows[0], k)).collect();
        // Fixture src_ip: 10.9.9.9, 10.1.2.3, 8.8.8.8, 192.168.1.1, 8.8.4.4 -> 3 private.
        assert_eq!(got, ["0", "0", "0", "0", "0", "0", "3"], "{p:?}");
        let minute = cell(&ch, p, "* | where {user}=\"Alice\" | eval m=strftime(timestamp, \"%M\") | table m", "m").await;
        assert_eq!(minute, "10", "{p:?}");
    }
    ch.drop().await;
}

/// NAN-3055: an array field against a scalar in eval/if() uses `| where`'s
/// multivalue semantics (any element; `!=` = no element). On dev both forms
/// failed with "Array does not start with '[' character".
#[tokio::test]
async fn nan3055_eval_array_field_compares_any_element() {
    let Some(ch) = Ch::connect("nan3055arr").await else { return };
    for p in BOTH {
        for (pred, want) in [
            (r#"{tags}="T1110""#, "2"),
            (r#"{tags}!="t1110""#, "3"),
            (r#"{tags} IN ("t1110", "nope")"#, "2"),
            (r#"{tags} CONTAINS "privilege""#, "2"),
            (r#"{tags}=/^se.*privilege$/"#, "2"),
        ] {
            let q = format!("* | eval m=if({pred}, 1, 0) | stats sum(m) as s");
            assert_eq!(cell(&ch, p, &q, "s").await, want, "{p:?} `{pred}`");
        }
    }
    ch.drop().await;
}

/// NAN-3055: chained `| risk` pipes are one risk object (Splunk RBA). A pipe
/// without `entity=` inherits the previous entity; dev reset it to 'unknown'.
#[tokio::test]
async fn nan3055_chained_risk_pipe_inherits_the_entity() {
    let Some(ch) = Ch::connect("nan3055risk").await else { return };
    for p in BOTH {
        let q = "* | where {user}=\"Alice\" | risk score=10 entity={user} factor=\"a\" | risk score=5 factor=\"b\" \
                 | table risk_entity risk_score raw_risk_score";
        let rows = ch.rows(p, &npl(p, q)).await;
        assert_eq!(rows.len(), 1, "{p:?}");
        assert_eq!(
            (s(&rows[0], "risk_entity"), s(&rows[0], "risk_score"), s(&rows[0], "raw_risk_score")),
            ("Alice".into(), "15".into(), "15".into()),
            "{p:?}"
        );
    }
    ch.drop().await;
}

/// NAN-3328: the field validator and the SQL generator read ONE registry of
/// the columns a command creates. Probe on dev, OCSF profile: these
/// command-created columns were rejected as unknown fields downstream.
#[test]
fn nan3328_command_created_columns_are_valid_downstream() {
    use nanosiem_core::query::parse_query;
    use nanosiem_core::query::validation::validate_query_fields_with_profile;
    use nanosiem_core::schema::{OcsfProfile, SchemaProfile};
    let profile = OcsfProfile::new();
    for query in [
        "* | lateral | where hop_number > 0 | table method_detail, hop_number",
        "* | risk score=10 entity=user.name | table risk_entity, raw_risk_score",
        "* | anomaly field=traffic.bytes_out | table avg_val, stddev_val",
        "* | anomaly field=traffic.bytes_out method=mad | table median_val, mad_val",
        "* | bin span=1h hop=30m | stats count by time_bucket_end",
        "* | table user.name as u, time | sort u",
    ] {
        let errors = validate_query_fields_with_profile(&parse_query(query).unwrap(), Some(&profile as &dyn SchemaProfile));
        assert!(errors.is_empty(), "{query}: {errors:?}");
    }
}

/// NAN-3316: OCSF wildcards expand against OCSF paths. On dev
/// `table src_endpoint.*` was "no fields match" on ocsf_logs.
#[tokio::test]
async fn nan3316_ocsf_wildcards_expand_against_ocsf_paths() {
    let Some(ch) = Ch::connect("nan3316").await else { return };
    let rows = ch.rows(Profile::Ocsf, "* | where actor.user.name=\"Alice\" | table src_endpoint.*, dst_endpoint.port").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(s(&rows[0], "src_endpoint.ip"), "10.1.2.3");
    assert_eq!(s(&rows[0], "dst_endpoint.port"), "443");
    assert!(rows[0].as_object().unwrap().keys().all(|k| k.starts_with("src_endpoint.") || k == "dst_endpoint.port"), "{:?}", rows[0]);
    ch.drop().await;
}

/// NAN-3336: a rename onto a column that already exists replaces it. On dev
/// `rename src_endpoint.ip as actor.user.name` kept `Alice` on ocsf_logs:
/// `SELECT *, a AS "actor.user.name"` left the source column in place.
#[tokio::test]
async fn nan3336_rename_onto_an_existing_column_replaces_it() {
    let Some(ch) = Ch::connect("nan3336").await else { return };
    for p in BOTH {
        let q = npl(p, "* | where {user}=\"Alice\" | rename {src_ip} as {user} | table {user}");
        assert_eq!(column(&ch.rows(p, &q).await, f(p, "user")), ["10.1.2.3"], "{p:?}");
        let q = npl(p, "* | where {user}=\"Alice\" | rename {src_ip} as {user} | stats count by {user}");
        assert_eq!(column(&ch.rows(p, &q).await, f(p, "user")), ["10.1.2.3"], "{p:?}");
    }
    ch.drop().await;
}

/// NAN-3312: `bin bins=N` on the time column is a round span giving at most N
/// buckets over the window; on a non-time field it is an error. On dev
/// `bin timestamp bins=4` failed in ClickHouse (DateTime64 / UInt8) and
/// `bin <numeric> bins=4` silently left the values unbinned.
#[tokio::test]
async fn nan3312_bin_bins_is_a_bounded_time_span() {
    let Some(ch) = Ch::connect("nan3312").await else { return };
    for p in BOTH {
        // 1h window / 4 bins -> 15m buckets. Events at minutes 0, 10, 20, 30, 40.
        let rows = ch.rows(p, "* | bin timestamp bins=4 | stats count by timestamp | sort timestamp").await;
        assert_eq!(column(&rows, "timestamp"), ["2026-10-01 00:00:00", "2026-10-01 00:15:00", "2026-10-01 00:30:00"], "{p:?}");
        assert_eq!(column(&rows, "count"), ["2", "1", "2"], "{p:?}: {rows:?}");
        let err = ch.sql(p, &npl(p, "* | bin {bytes_in} bins=4 | stats count by {bytes_in}"), &window()).unwrap_err();
        assert!(err.contains("bins= is only supported for the time field"), "{p:?}: {err}");
    }
    ch.drop().await;
}

/// NAN-3313: isnum / isint / isstr / isbool / searchmatch exist in eval and
/// where. On dev each was "Unknown eval function".
#[tokio::test]
async fn nan3313_type_tests_and_searchmatch() {
    let Some(ch) = Ch::connect("nan3313").await else { return };
    for p in BOTH {
        let q = "* | where {user}=\"Alice\" | eval a=isnum({bytes_in}), b=isint({bytes_in}), c=isstr({user}), d=isnum({user}) | table a b c d";
        let rows = ch.rows(p, &npl(p, q)).await;
        let got: Vec<String> = ["a", "b", "c", "d"].iter().map(|k| s(&rows[0], k)).collect();
        assert_eq!(got, ["1", "1", "1", "0"], "{p:?}");
        let q = "* | eval m=if(searchmatch(\"{user}=bo*\"), 1, 0) | stats sum(m) as s";
        assert_eq!(cell(&ch, p, q, "s").await, "2", "{p:?}");
        assert_eq!(cell(&ch, p, "* | where searchmatch(\"{user}=ALI*\") | stats count", "count").await, "1", "{p:?}");
    }
    ch.drop().await;
}

/// NAN-3315: piped `| search f=val*` uses the base search's wildcard
/// semantics. On dev it compared the glob literally (0 rows; `!=` all rows).
#[tokio::test]
async fn nan3315_piped_search_wildcards() {
    let Some(ch) = Ch::connect("nan3315").await else { return };
    for p in BOTH {
        assert_eq!(cell(&ch, p, "* | search {user}=bo* | stats count", "count").await, "2", "{p:?}");
        assert_eq!(cell(&ch, p, "* | search {user}=B?B | stats count", "count").await, "2", "{p:?}");
        assert_eq!(cell(&ch, p, "* | search {user}!=bo* | stats count", "count").await, "3", "{p:?}");
    }
    ch.drop().await;
}

/// NAN-3324: unparenthesized arithmetic in `where` is a predicate. On dev
/// `where bytes_in * 2 > 1000` was a parse error. NAN-3326: base64_decode of
/// junk is NULL, not a failed search (dev: INCORRECT_DATA).
#[tokio::test]
async fn nan3324_where_arithmetic_and_nan3326_base64_decode() {
    let Some(ch) = Ch::connect("nan3324").await else { return };
    for p in BOTH {
        assert_eq!(cell(&ch, p, "* | where {bytes_in} * 2 > 1000 | stats count", "count").await, "1", "{p:?}");
        assert_eq!(cell(&ch, p, "* | where {bytes_in} + 100 >= 400 | stats count", "count").await, "2", "{p:?}");
        let q = "* | where {user}=\"Alice\" | eval d=base64_decode(\"!!!notb64\"), e=base64_decode(\"aGk=\") | table d e";
        let rows = ch.rows(p, &npl(p, q)).await;
        assert_eq!((s(&rows[0], "d"), s(&rows[0], "e")), ("null".into(), "hi".into()), "{p:?}");
    }
    ch.drop().await;
}

/// NAN-3319: a sort key written as the aggregate (`sort -count(f)`) names the
/// stats output column; the validator rejected it as an unknown field.
#[test]
fn nan3319_sort_by_aggregate_validates() {
    use nanosiem_core::query::parse_query;
    use nanosiem_core::query::validation::validate_query_fields_with_profile;
    use nanosiem_core::schema::{OcsfProfile, SchemaProfile};
    let profile = OcsfProfile::new();
    let q = "* | stats count(traffic.bytes_in), max(traffic.bytes_in) by actor.user.name | sort -count(traffic.bytes_in), max(traffic.bytes_in)";
    let errors = validate_query_fields_with_profile(&parse_query(q).unwrap(), Some(&profile as &dyn SchemaProfile));
    assert!(errors.is_empty(), "{errors:?}");
}

/// NAN-3329: datetime operands of arithmetic are epoch seconds. On dev
/// `eval age=now()-timestamp` and `eval t=timestamp+60` were NULL on every row.
#[tokio::test]
async fn nan3329_time_arithmetic_is_epoch_seconds() {
    let Some(ch) = Ch::connect("nan3329time").await else { return };
    for p in BOTH {
        let q = "* | where {user}=\"Alice\" | eval age=now()-timestamp, t=timestamp+60, d=timestamp-timestamp | table age t d";
        let rows = ch.rows(p, &npl(p, q)).await;
        let age: i64 = s(&rows[0], "age").parse().unwrap_or_else(|_| panic!("{p:?}: {rows:?}"));
        assert!(age > 0, "{p:?}: {age}");
        // Alice is 2026-10-01 00:10:00 UTC = 1790813400.
        assert_eq!(s(&rows[0], "t").parse::<f64>().unwrap(), 1_790_813_460.0, "{p:?}");
        assert_eq!(s(&rows[0], "d"), "0", "{p:?}");
        assert_eq!(cell(&ch, p, "* | eval age=now()-timestamp | where age > 0 | stats count", "count").await, "5", "{p:?}");
    }
    ch.drop().await;
}

/// NAN-3329: a dotted field after an ordering operator is a field reference.
/// On dev `traffic.bytes_in > dst_endpoint.port` compared against the text
/// 'dst_endpoint.port' and failed in ClickHouse (TYPE_MISMATCH).
#[tokio::test]
async fn nan3329_dotted_field_after_an_ordering_operator() {
    let Some(ch) = Ch::connect("nan3329dot").await else { return };
    // bytes_in vs dest_port: 50>22, 900>443, 200>80, 300<443, 100>53.
    assert_eq!(cell(&ch, Profile::Ocsf, "* | where traffic.bytes_in > dst_endpoint.port | stats count", "count").await, "4");
    assert_eq!(cell(&ch, Profile::Ocsf, "traffic.bytes_in > dst_endpoint.port | stats count", "count").await, "4");
    assert_eq!(cell(&ch, Profile::Udm, "* | where bytes_in > dest_port | stats count", "count").await, "4");
    ch.drop().await;
}

/// NAN-3329: `streamstats window=N` covers N events, and `current=false`
/// value functions are NULL on the first event. On dev window=2 counted 3,
/// and the first event's `last()` wrapped around to another row's value.
#[tokio::test]
async fn nan3329_streamstats_window_and_current_false() {
    let Some(ch) = Ch::connect("nan3329ss").await else { return };
    for p in BOTH {
        let rows = ch.rows(p, &npl(p, "* | sort timestamp | streamstats window=2 count as c, sum({bytes_in}) as s | table {bytes_in} c s")).await;
        assert_eq!(column(&rows, "c"), ["1", "2", "2", "2", "2"], "{p:?}: {rows:?}");
        assert_eq!(column(&rows, "s"), ["50", "950", "1100", "500", "400"], "{p:?}: {rows:?}");
        let rows = ch.rows(p, &npl(p, "* | sort timestamp | streamstats current=false last({bytes_in}) as prev | table prev")).await;
        assert_eq!(column(&rows, "prev"), ["null", "50", "900", "200", "300"], "{p:?}");
    }
    ch.drop().await;
}

/// NAN-3329: `top … showcount=false` / `rare … showperc=false`. On dev
/// `top showcount=false` failed in ClickHouse (Unknown identifier `count`).
#[tokio::test]
async fn nan3329_top_showcount_false() {
    let Some(ch) = Ch::connect("nan3329top").await else { return };
    for p in BOTH {
        let rows = ch.rows(p, &npl(p, "* | top limit=1 {user} showcount=false")).await;
        assert_eq!(column(&rows, f(p, "user")), ["bob"], "{p:?}");
        assert!(rows[0].get("count").is_none() && rows[0].get("percent").is_some(), "{p:?}: {rows:?}");
    }
    ch.drop().await;
}

/// NAN-3327: rex named groups take their index among ALL capturing groups,
/// `mode=sed` rewrites the field in place, and `spath input=raw_data` walks a
/// dotted path into the column's JSON text. On dev `(?<a>w)(i)(?<b>n)` gave
/// b="i", sed left `message` unchanged (it added `rex_result`).
#[tokio::test]
async fn nan3327_rex_groups_sed_and_spath_raw_data() {
    let Some(ch) = Ch::connect("nan3327").await else { return };
    for p in BOTH {
        let q = "* | where {user}=\"erin\" | rex field={message} \"(?<a>w)(i)(?<b>n)\" | table a b";
        let rows = ch.rows(p, &npl(p, q)).await;
        assert_eq!((s(&rows[0], "a"), s(&rows[0], "b")), ("w".into(), "n".into()), "{p:?}");
        let q = "* | where {user}=\"erin\" | rex field={message} mode=sed \"s/window/WIN/\" | table {message}";
        assert_eq!(cell(&ch, p, q, f(p, "message")).await, "WIN start", "{p:?}");
    }
    ch.insert(
        Profile::Ocsf,
        &[r#"{"timestamp":"2026-10-01 00:55:00.000","source_type":"fixture","class_uid":4001,"metadata.uid":"uid-json","actor.user.name":"json","raw_data":"{\"a\":{\"b\":\"deep\"},\"c\":\"top\"}"}"#.to_string()],
    )
    .await;
    let q = "* | where actor.user.name=\"json\" | spath input=raw_data output=x path=a.b | spath input=raw_data output=y path=c | table x y";
    let rows = ch.rows(Profile::Ocsf, q).await;
    assert_eq!((s(&rows[0], "x"), s(&rows[0], "y")), ("deep".into(), "top".into()), "{rows:?}");
    ch.drop().await;
}

/// NAN-3338: `sequence_count` counts completed sequences. On dev bob's one
/// 7 -> 500 sequence reported sequence_count=2 (the matching events).
#[tokio::test]
async fn nan3338_sequence_count_counts_completed_sequences() {
    let Some(ch) = Ch::connect("nan3338").await else { return };
    for p in BOTH {
        let q = npl(p, "* | sequence by {user} maxspan=1h [{status}=\"7\"] [{status}=\"500\"]");
        let rows = ch.rows(p, &q).await;
        assert_eq!(rows.len(), 1, "{p:?}: {rows:?}");
        assert_eq!((s(&rows[0], "sequence_count"), s(&rows[0], "sequence_duration_seconds")), ("1".into(), "1200".into()), "{p:?}");
        assert_eq!(s(&rows[0], "step2_status"), "500", "{p:?}");
    }
    ch.drop().await;
}

/// NAN-3337: `earliest=`/`latest=` inside a `[ ]` subsearch is rejected; on
/// dev it was stripped from the subsearch and applied to the OUTER range.
#[test]
fn nan3337_subsearch_time_modifiers_are_rejected() {
    use nanosiem_core::query::parse_query;
    let err = parse_query("class_uid=3002 | stats count as main | append [search class_uid=3002 earliest=-3h latest=-2h | stats count as sub]")
        .expect_err("subsearch modifiers must be rejected");
    assert!(err.message.contains("subsearch"), "{}", err.message);
    assert!(parse_query("a earliest=-1h | append [search b | stats count]").is_ok());
    assert!(parse_query("a | append [search b is_latest=true | stats count]").is_ok());
}

/// NAN-3338 (806bc41ff): the sequence run walk ported with batch C (the
/// in-maxspan run and sequence_count) must read no outer array inside a
/// lambda: a captured array is copied once per element, O(events^2) memory per
/// group. Guard, not a dev repro: dev had no run walk, so it passes there too;
/// this pins the ported shape on a busy group under a 300 MB cap.
#[tokio::test]
async fn nan3338_sequence_on_a_busy_group_stays_linear() {
    let Some(ch) = Ch::connect("nan3338big").await else { return };
    let rows: Vec<String> = (0..8000)
        .map(|i| {
            let ts = (t0() + chrono::Duration::milliseconds(i * 400)).format("%Y-%m-%d %H:%M:%S%.3f");
            let status = if i % 2 == 0 { "7" } else { "500" };
            format!(r#"{{"timestamp":"{ts}","source_type":"fixture","class_uid":4001,"metadata.uid":"big-{i}","actor.user.name":"busy","status":"{status}"}}"#)
        })
        .collect();
    ch.insert(Profile::Ocsf, &rows).await;
    let q = "actor.user.name=\"busy\" | sequence by actor.user.name maxspan=5m [status=\"7\"] [status=\"500\"]";
    let sql = ch.sql(Profile::Ocsf, q, &window()).unwrap();
    let rows = ch
        .try_rows(&format!("{sql}\nSETTINGS max_memory_usage = 300000000"))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(s(&rows[0], "step1_status"), "7");
    ch.drop().await;
}

// ---------------------------------------------------------------------------
// NAN-4933 codex review: SQL vs Nano-side (post-processing) parity. Every case
// runs the same pipeline twice on real ClickHouse: wholly in SQL, and with the
// suffix replayed by the Nano-side evaluator over the rows ClickHouse returns
// for the prefix — exactly what happens after a prevalence / inputlookup /
// lateral / ai / lookup boundary. OCSF first; UDM only where the bug is UDM.
// ---------------------------------------------------------------------------

fn suffix_commands(suffix: &str) -> Vec<nanosiem_core::query::Command> {
    use nanosiem_core::query::{parse_query, Query};
    let mut out = Vec::new();
    let mut node = parse_query(&format!("* | {suffix}")).unwrap();
    while let Query::Piped { source, command } = node {
        out.push(command);
        node = *source;
    }
    out.reverse();
    out
}

/// `prefix | suffix` in SQL vs `prefix` in SQL then `suffix` Nano-side; the
/// sorted `key` column must be identical (and is returned).
async fn boundary_parity(ch: &Ch, p: Profile, prefix: &str, suffix: &str, key: &str) -> Vec<String> {
    let (prefix, suffix) = (npl(p, prefix), npl(p, suffix));
    let mut in_sql = column(&ch.rows(p, &format!("{prefix} | {suffix}")).await, key);
    let rows = ch.rows(p, &prefix).await;
    let replayed = nanosiem_core::search::apply_post_prevalence_commands(rows, &suffix_commands(&suffix))
        .unwrap_or_else(|e| panic!("{p:?} Nano-side `{suffix}`: {e}"))
        .results;
    let mut nano = column(&replayed, key);
    in_sql.sort();
    nano.sort();
    assert_eq!(in_sql, nano, "{p:?} `{prefix} | {suffix}`: SQL vs Nano-side");
    in_sql
}

/// Codex P1-4: piped `| search f=val*` after a Nano-side stage returned no
/// rows (the evaluator had no LIKE arm).
#[tokio::test]
async fn parity_piped_search_wildcards_across_a_boundary() {
    let Some(ch) = Ch::connect("pbsearch").await else { return };
    let p = Profile::Ocsf;
    let hit = boundary_parity(&ch, p, "*", "search actor.user.name=ALI* | table actor.user.name", "actor.user.name").await;
    assert_eq!(hit, ["Alice"]);
    let hit = boundary_parity(&ch, p, "*", "search device.hostname=ws-? | search actor.user.name!=bo* | table actor.user.name", "actor.user.name").await;
    assert_eq!(hit, ["Alice", "carol", "erin"]);
    // Array element: any element matches (SQL arrayExists).
    let hit = boundary_parity(&ch, p, "*", "search resources.type=sedeb* | table actor.user.name", "actor.user.name").await;
    assert_eq!(hit, ["Alice"]);
    // UDM-compat alias on OCSF (`user` -> user_unified) in SQL.
    assert_eq!(cell(&ch, p, "* | search user=ali* | stats count", "count").await, "1");
    ch.drop().await;
}

/// Codex P2: an array path in piped search escaped the generated `%` a second
/// time and matched the literal text `sedeb%`.
#[tokio::test]
async fn array_path_piped_wildcard_is_not_double_escaped() {
    let Some(ch) = Ch::connect("pbarr").await else { return };
    assert_eq!(cell(&ch, Profile::Ocsf, "* | search resources.type=sedeb* | stats count", "count").await, "1");
    assert_eq!(cell(&ch, Profile::Ocsf, "* | search resources.type!=sedeb* | stats count", "count").await, "4");
    ch.drop().await;
}

/// Codex P1-5: an array field against a scalar in eval returned NULL
/// Nano-side, so a flag computed after `| prevalence` never matched.
#[tokio::test]
async fn parity_eval_array_compares_across_a_boundary() {
    let Some(ch) = Ch::connect("pbarray").await else { return };
    let p = Profile::Ocsf;
    for (pred, want) in [
        (r#"resources.type="T1110""#, vec!["Alice", "bob"]),
        (r#"resources.type!="t1110""#, vec!["bob", "carol", "erin"]),
        (r#"resources.type CONTAINS "privilege""#, vec!["Alice", "bob"]),
        (r#"resources.type=/^se.*privilege$/"#, vec!["Alice", "bob"]),
        (r#"resources.type IN ("t1110", "x")"#, vec!["Alice", "bob"]),
    ] {
        let suffix = format!("eval m=if({pred}, 1, 0) | where m=1 | table actor.user.name");
        let got = boundary_parity(&ch, p, "*", &suffix, "actor.user.name").await;
        let want: Vec<String> = want.into_iter().map(String::from).collect();
        assert_eq!(got, want, "`{pred}`");
    }
    ch.drop().await;
}

/// Codex P2: isnum / isint / isstr / isbool / searchmatch Nano-side, with
/// the SQL semantics (they were "unsupported function" after a boundary).
#[tokio::test]
async fn parity_type_tests_and_searchmatch_across_a_boundary() {
    let Some(ch) = Ch::connect("pbtype").await else { return };
    let p = Profile::Ocsf;
    let got = boundary_parity(&ch, p, "*", r#"where searchmatch("actor.user.name=bo*") | table actor.user.name"#, "actor.user.name").await;
    assert_eq!(got, ["bob", "bob"]);
    let got = boundary_parity(&ch, p, "*", "where isstr(actor.user.name) AND NOT isnum(actor.user.name) | table actor.user.name", "actor.user.name").await;
    assert_eq!(got.len(), 5);
    let got = boundary_parity(&ch, p, "*", "eval n=\"42\" | where isnum(n) AND isint(n) AND isstr(n) | table actor.user.name", "actor.user.name").await;
    assert_eq!(got.len(), 5);
    ch.drop().await;
}

/// Codex P2 (UDM-specific): `isbool` on a UDM boolean stored as UInt8.
#[tokio::test]
async fn isbool_on_udm_uint8_booleans() {
    let Some(ch) = Ch::connect("pbbool").await else { return };
    assert_eq!(cell(&ch, Profile::Udm, "* | where isbool(ioc_matched) | stats count", "count").await, "5");
    assert_eq!(cell(&ch, Profile::Udm, "* | where isbool(user) | stats count", "count").await, "0");
    ch.drop().await;
}

/// Codex P2: Python-style `(?P<name>…)` rex groups Nano-side (they silently
/// extracted nothing), with the SQL's '' for a non-matching row.
#[tokio::test]
async fn parity_rex_python_named_groups_across_a_boundary() {
    let Some(ch) = Ch::connect("pbrex").await else { return };
    let p = Profile::Ocsf;
    let got = boundary_parity(&ch, p, "*", r#"rex field=message "(?P<w>win\w+)" | table w"#, "w").await;
    assert_eq!(got.iter().filter(|w| w.as_str() == "window").count(), 1);
    ch.drop().await;
}

/// Codex P2: chained renames are SEQUENTIAL in SQL and Nano-side.
#[tokio::test]
async fn parity_chained_rename_across_a_boundary() {
    let Some(ch) = Ch::connect("pbren").await else { return };
    let p = Profile::Ocsf;
    let prefix = "* | where actor.user.name=\"Alice\"";
    let got = boundary_parity(&ch, p, prefix, "rename actor.user.name AS a, a AS c | table c", "c").await;
    assert_eq!(got, ["Alice"]);
    let got = boundary_parity(&ch, p, prefix, "rename src_endpoint.ip AS x, device.hostname AS src_endpoint.ip | table src_endpoint.ip", "src_endpoint.ip").await;
    assert_eq!(got, ["ws-1"]);
    ch.drop().await;
}

/// Codex P2: `?` stays inside a bounded term; `**` is the match-all `*`.
#[tokio::test]
async fn question_mark_keeps_term_boundaries_and_all_wildcard_is_match_all() {
    let Some(ch) = Ch::connect("pbkw").await else { return };
    let p = Profile::Ocsf;
    assert_eq!(cell(&ch, p, "?md.exe | stats count", "count").await, "1");
    assert_eq!(cell(&ch, p, "?d.exe | stats count", "count").await, "0");
    assert_eq!(cell(&ch, p, "windo? | stats count", "count").await, "1");
    assert_eq!(cell(&ch, p, "wind? | stats count", "count").await, "0");
    assert_eq!(cell(&ch, p, "** | stats count", "count").await, "5");
    let sql = ch.sql(p, "** | stats count", &window()).unwrap();
    assert!(!sql.contains("LIKE '%%'"), "{sql}");
    ch.drop().await;
}

/// Codex P1-1/2/3: lookup is a Nano-side boundary. The prefix runs in
/// ClickHouse, the lookup merges (event field first, CASE_INSENSITIVE folded),
/// and the suffix replays after it; an unorderable shape is refused.
#[tokio::test]
async fn lookup_is_a_nano_side_boundary() {
    use nanosiem_core::query::parse_query;
    use nanosiem_core::search::query_processing::{
        extract_lookup_commands, extract_post_enrichment_commands, lookup_boundary_plan,
        strip_enrichment_and_after,
    };
    use nanosiem_core::PrettyPrint;
    let Some(ch) = Ch::connect("pblookup").await else { return };
    let p = Profile::Ocsf;
    // A computed event field (dev's grammar: event field AS lookup key).
    let q = parse_query(
        r#"* | eval emp=actor.user.name | lookup hr emp AS id OUTPUT dept AS department CASE_INSENSITIVE | where department="it" | stats count by department"#,
    )
    .unwrap();
    assert_eq!(lookup_boundary_plan(&q), Ok(true));
    let prefix = strip_enrichment_and_after(&q).pretty_print();
    let mut rows = ch.rows(p, &prefix).await;
    let lookup = extract_lookup_commands(&q).remove(0);
    assert_eq!((lookup.event_field.as_str(), lookup.key_field.as_str()), ("emp", "id"));
    // The table's spelling differs from the events' (`Alice`, `bob`).
    let mut batch = nanosiem_core::lookup::BatchLookupResult { results: Default::default(), matched_count: 2, total_count: 2 };
    batch.results.insert("ALICE".into(), [("dept".to_string(), serde_json::json!("it"))].into_iter().collect());
    batch.results.insert("BOB".into(), [("dept".to_string(), serde_json::json!("it"))].into_iter().collect());
    nanosiem_core::search::merge_lookup_batch(&mut rows, &lookup, &batch);
    let out = nanosiem_core::search::apply_post_prevalence_commands(rows, &extract_post_enrichment_commands(&q))
        .unwrap()
        .results;
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!((s(&out[0], "department"), s(&out[0], "count")), ("it".into(), "3".into()), "{out:?}");
    // An unorderable shape is a clear refusal, never a wrong answer.
    let q = parse_query(r#"* | lookup hr actor.user.name AS id OUTPUT dept | where dept="it" | prevalence enrich=true"#).unwrap();
    assert!(lookup_boundary_plan(&q).is_err());
    ch.drop().await;
}
