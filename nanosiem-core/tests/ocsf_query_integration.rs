// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! OCSF Phase 4 (NAN-1241) — end-to-end queryability proof.
//!
//! This is the "OCSF is actually queryable" gate: it drives **real nPL → SQL
//! through `ClickHouseSqlGenerator` with an `OcsfProfile`**, executes the
//! generated SQL against the canonical OCSF table (`clickhouse/ocsf/init.sql`)
//! loaded with the spec-compliant fixtures, and asserts concrete row
//! counts/values derived from those fixtures.
//!
//! It proves the two resolution paths Phase 4 owns:
//!   * a **promoted dotted column** (`src_endpoint.ip`) resolves to a quoted
//!     direct column and hits the indexed `"src_endpoint.ip"` column, and
//!   * an **unpromoted tail field** (`actor.process.parent_process.name`)
//!     resolves to `JSONExtractString(event, 'actor', 'process', …)` against the
//!     `event` JSON spill.
//!
//! Plus: full-text keyword on `message`, `stats count by` a promoted column, a
//! promoted enrichment field, and the `class_uid` taxonomy int.
//!
//! Requires a local ClickHouse with DDL rights (admin
//! nanosiem_admin/nanosiem_admin_secret @ :8123). Skips cleanly if unreachable
//! or if `SKIP_DB_TESTS` is set. Reuses the proven insert pattern from
//! `ocsf_materialization_integration` (statement in `?query=` + synchronous
//! insert; data in body) and a per-run throwaway DB with the TTL stripped.
//!   Run: cargo test -p nanosiem-core --test ocsf_query_integration -- --nocapture

use std::sync::Arc;

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::OcsfProfile;
use serde_json::Value;

const DDL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));

/// All six spec-compliant fixtures (multi-class corpus).
const FIXTURES: &[(&str, &str)] = &[
    (
        "auth",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/authentication_3002_logon.json"
        )),
    ),
    (
        "network",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/network_activity_4001_traffic.json"
        )),
    ),
    (
        "process",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/process_activity_1007_launch.json"
        )),
    ),
    (
        "file",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/file_activity_1001_delete.json"
        )),
    ),
    (
        "dns",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/dns_activity_4003_query.json"
        )),
    ),
    (
        "http",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/http_activity_4002_get.json"
        )),
    ),
];

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}
fn ch_user() -> String {
    std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or_else(|_| "nanosiem_admin".into())
}
fn ch_pass() -> String {
    std::env::var("CLICKHOUSE_ADMIN_PASSWORD").unwrap_or_else(|_| "nanosiem_admin_secret".into())
}

/// A wide time range covering all fixture `time` values. OCSF `time` is epoch
/// **ms**; the fixtures use `1749081600123…` which is 2025-06-05 (NOT 2026 — the
/// epoch-ms is what matters, and the DEFAULT derives `timestamp` from it).
fn fixture_time_range() -> TimeRange {
    TimeRange {
        start: "2025-06-01T00:00:00Z".parse().unwrap(),
        end: "2025-06-10T00:00:00Z".parse().unwrap(),
    }
}

/// Build SQL from nPL via the OCSF-profiled generator against `<db>.ocsf_logs`.
fn ocsf_sql(npl: &str, db: &str) -> String {
    let query = parse_query(npl).unwrap_or_else(|e| panic!("parse failed for `{npl}`: {e}"));
    let gen = ClickHouseSqlGenerator::with_table(format!("{db}.ocsf_logs"))
        .with_profile(Arc::new(OcsfProfile::new()));
    gen.generate(&query, &fixture_time_range())
        .unwrap_or_else(|e| panic!("SQL gen failed for `{npl}`: {e}"))
}

/// NAN-1337 regression (pure SQL-gen, no DB): a multi-stage query that GROUP BYs a
/// CLASS-SPLIT concept (`src_host` → `src_host_unified`) must project the unified
/// column in the base CTE so the later GROUP BY stage can reference it. Before the
/// fix `stage_0` (`SELECT *` + the manifest-built re-add list) omitted
/// `src_host_unified` — because it's MATERIALIZED but not a manifest column — so
/// execution failed with CH Code 47 "Unknown identifier `src_host_unified`". The
/// fix appends the unified columns to the re-add list. Assert the unified column
/// appears at least twice (base-CTE projection + the GROUP BY/stats stage).
/// NAN-1340 regression (pure SQL-gen, no DB): a 2-arg `tostring(value, "<strftime>")`
/// must honor the format via `formatDateTime`, not silently drop it and stringify
/// the whole value. Before the fix `tostring(timestamp, "%H")` emitted
/// `toString(timestamp)`, so `| stats … by hour` grouped on the full timestamp
/// string (thousands of groups) instead of the hour-of-day.
#[test]
fn tostring_with_strftime_format_uses_format_date_time() {
    let sql = ocsf_sql(r#"* | eval hour = tostring(timestamp, "%H") | stats count by hour"#, "nanosiem");
    assert!(
        sql.contains("formatDateTime(timestamp, '%H')"),
        "tostring(ts, \"%H\") must format via formatDateTime (NAN-1340); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("toString(timestamp) AS hour"),
        "tostring must not silently drop the format arg (NAN-1340); SQL:\n{sql}"
    );
}

/// NAN-1343 regression (pure SQL-gen, no DB): `spath input=ext` must extract from the
/// active profile's JSON tail — `event` under OCSF, not the literal `ext` column (which
/// does not exist under OCSF and 500s with Code 47). The input column is resolved through
/// the profile: a tail name (`ext`/`event`) targets `json_tail_column()`.
#[test]
fn spath_input_ext_targets_ocsf_event_tail() {
    let sql = ocsf_sql(
        r#"* | spath input=ext path="request.method" output=method | stats count() by method"#,
        "nanosiem",
    );
    assert!(
        sql.contains("JSONExtractString(event, 'request.method')"),
        "spath must extract from the OCSF `event` tail (NAN-1343); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("JSONExtractString(ext,"),
        "spath must not reference the nonexistent OCSF `ext` column (NAN-1343); SQL:\n{sql}"
    );
}

/// NAN-1344 regression (pure SQL-gen, no DB): `chart … over X by Y` must group by
/// exactly [X, Y] — the clause keyword `by` must not leak into the group list (which
/// would emit a `by` column reference and 500 with Code 47). The over-clause field
/// list now stops at `by`.
#[test]
fn chart_over_does_not_leak_by_keyword_as_group_field() {
    let sql = ocsf_sql("* | chart count() over src_endpoint.ip by source_type", "nanosiem");
    assert!(
        !sql.contains(", by,") && !sql.contains(" by AS ") && !sql.contains("GROUP BY by"),
        "chart over/by must not leak `by` as a group field (NAN-1344); SQL:\n{sql}"
    );
    assert!(
        sql.contains("source_type"),
        "chart over/by must still group by the split field `source_type`; SQL:\n{sql}"
    );
}

/// NAN-1345 regression (pure SQL-gen, no DB): `anomaly sum(<field>)` must resolve the
/// inner field through the active profile. `bytes_in` is a UDM name; under OCSF it is
/// `traffic.bytes_in`, so the raw form 500s with Code 47. `count()` passes through.
#[test]
fn anomaly_aggregation_field_resolves_under_ocsf() {
    let sql = ocsf_sql("* | anomaly sum(bytes_in) by src_endpoint.ip span=15m", "nanosiem");
    assert!(
        sql.contains("sum(\"traffic.bytes_in\")") || sql.contains("traffic.bytes_in"),
        "anomaly agg field must resolve to the OCSF column (NAN-1345); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("sum(bytes_in)"),
        "anomaly must not emit the raw UDM `bytes_in` under OCSF (NAN-1345); SQL:\n{sql}"
    );
}

/// NAN-1346 regression (pure SQL-gen, no DB): a `sequence` step capture must resolve
/// the captured field through the active profile. `action` is a UDM name with no OCSF
/// column, so the raw `argMinIf(action, …)` 500s with Code 47; it must resolve to the
/// OCSF equivalent (`activity`).
#[test]
fn sequence_capture_field_resolves_under_ocsf() {
    let sql = ocsf_sql(
        r#"* | sequence by user.name maxspan=30m [action="login"] [action="privilege_escalation"]"#,
        "nanosiem",
    );
    assert!(
        !sql.contains("argMinIf(action,") && !sql.contains("tuple(toUInt32(timestamp), id, action,"),
        "sequence must not capture the raw UDM `action` column under OCSF (NAN-1346); SQL:\n{sql}"
    );
    assert!(
        sql.contains("activity"),
        "sequence capture of `action` must resolve to the OCSF `activity` column (NAN-1346); SQL:\n{sql}"
    );
}

/// NAN-1346 regression (pure SQL-gen, no DB): the funnel argMax's a fixed set of
/// "dropper attribute" columns (process_name, …) that never appear in the query text.
/// They must be declared required so field pruning keeps the resolved column
/// (process_name_unified under OCSF) in stage_0 — otherwise the argMax 500s with Code 47.
#[test]
fn funnel_dropper_columns_survive_field_pruning_under_ocsf() {
    let sql = ocsf_sql(
        r#"* | funnel by user.name maxspan=1h [action="login"] [action="search"]"#,
        "nanosiem",
    );
    // The base CTE (stage_0) ends at the first ` FROM `. The unified dropper column the
    // funnel argMax references must be projected there.
    let first_from = sql.find(" FROM ").expect("generated SQL must have a FROM");
    let stage0 = &sql[..first_from];
    assert!(
        stage0.contains("process_name_unified"),
        "funnel dropper column must survive pruning in stage_0 (NAN-1346); stage_0:\n{stage0}"
    );
}

#[test]
fn stats_by_class_split_projects_unified_column_through_cte() {
    let sql = ocsf_sql("* | stats count by src_host", "nanosiem");
    // The base CTE (`stage_0`) ends at the first `FROM <table>`. The later stats
    // stage does `SELECT src_host_unified … FROM stage_0 GROUP BY src_host_unified`,
    // so the unified column MUST appear in stage_0's projection — i.e. before that
    // first FROM — or execution fails (CH Code 47). Counting occurrences is not
    // enough: the GROUP-BY stage mentions it twice on its own.
    let first_from = sql.find(" FROM ").expect("generated SQL must have a FROM");
    let stage0_projection = &sql[..first_from];
    assert!(
        stage0_projection.contains("src_host_unified"),
        "base CTE must project src_host_unified for the later GROUP BY (NAN-1337); \
         stage_0 projection:\n{stage0_projection}\n--- full SQL ---\n{sql}"
    );
}

/// NAN-1339 regression (pure SQL-gen, no DB): a `rename`'d field referenced by a
/// downstream `| table` must resolve as a real column, NOT be JSON-extracted from
/// the OCSF `event` tail. Before the fix `collect_computed_field_names` had no
/// `Command::Rename` arm, so the alias was unknown to `field_to_sql_expr`, which
/// fell back to `JSONExtractString(event, 'scanner')` — and `event` has already
/// been dropped by the upstream GROUP BY, so execution failed (CH Code 47).
#[test]
fn rename_alias_is_real_column_not_json_extracted_from_tail() {
    let sql = ocsf_sql(
        "* | stats count() as n by src_endpoint.ip | rename src_endpoint.ip as scanner | table scanner, n",
        "nanosiem",
    );
    assert!(
        !sql.contains("event, 'scanner'") && !sql.contains("ext, 'scanner'"),
        "rename alias `scanner` must not be JSON-extracted from the tail (NAN-1339); SQL:\n{sql}"
    );
    assert!(
        sql.contains("scanner"),
        "rename alias `scanner` must appear as a projected column; SQL:\n{sql}"
    );
}

/// NAN-1339 regression: a `rex` named capture referenced downstream must resolve as
/// a real column, not be JSON-extracted from the `event` tail (no `Command::Rex`
/// arm in `collect_computed_field_names` before the fix).
#[test]
fn rex_named_capture_is_real_column_not_json_extracted_from_tail() {
    let sql = ocsf_sql(
        r#"* | rex "(?P<method>GET|POST)\s+(?P<path>/\S+)" | stats count() by method"#,
        "nanosiem",
    );
    assert!(
        !sql.contains("event, 'method'") && !sql.contains("ext, 'method'"),
        "rex capture `method` must not be JSON-extracted from the tail (NAN-1339); SQL:\n{sql}"
    );
}

/// NAN-1346 #3 regression (pure SQL-gen, no DB): an `append` whose arms are both
/// aggregations must UNION by *name* with NULL padding (align-by-name semantics) — a bare
/// positional `SELECT * … UNION ALL <sub>` either misaligns columns or fails with
/// CH Code 53 TYPE_MISMATCH when the group-by fields differ.
#[test]
fn append_aggregated_arms_union_by_name_with_null_padding() {
    let sql = ocsf_sql(
        "* | stats count() as events by src_endpoint.ip | append [search * | stats count() as events by dst_endpoint.ip]",
        "nanosiem",
    );
    assert!(
        sql.contains(r#"NULL AS "dst_endpoint.ip""#),
        "main arm must NULL-pad the subsearch-only column (NAN-1346 #3); SQL:\n{sql}"
    );
    assert!(
        sql.contains(r#"NULL AS "src_endpoint.ip""#),
        "subsearch arm must NULL-pad the main-only column (NAN-1346 #3); SQL:\n{sql}"
    );
}

/// NAN-1346 #3 regression (pure SQL-gen, no DB): the subsearch's base scan must use
/// the same select clause as the main pipeline's stage_0. A bare `SELECT *` omits
/// MATERIALIZED columns (ClickHouse excludes them from `*`), so a subsearch
/// `stats by dst_endpoint.ip` failed with Code 47 "Unknown expression identifier".
#[test]
fn append_subsearch_base_scan_projects_materialized_columns() {
    let sql = ocsf_sql(
        "* | stats count() as events by src_endpoint.ip | append [search * | stats count() as events by dst_endpoint.ip]",
        "nanosiem",
    );
    let union_at = sql.find("UNION ALL").expect("append must emit a UNION ALL");
    let sub_arm = &sql[union_at..];
    assert!(
        sub_arm.contains(r#"SELECT *, "#) && sub_arm.contains(r#""dst_endpoint.ip", "#),
        "subsearch base scan must re-add MATERIALIZED columns like the main stage_0 \
         (NAN-1346 #3); subsearch arm:\n{sub_arm}"
    );
}

/// NAN-1346 #3 regression (pure SQL-gen, no DB): a subsearch ending in its own LIMIT
/// (`head`) must not collide with the appended subsearch result cap —
/// `… LIMIT 5 LIMIT 10000` is a CH Code 62 syntax error. The cap wraps the stage SQL
/// in a subquery instead. Profile-independent (also broken under UDM).
#[test]
fn append_subsearch_with_head_does_not_double_limit() {
    let sql = ocsf_sql("* | head 5 | append [search class_uid=3002 | head 5]", "nanosiem");
    assert!(
        !sql.contains("LIMIT 5 LIMIT"),
        "subsearch cap must not stack onto the subsearch's own LIMIT (NAN-1346 #3); SQL:\n{sql}"
    );
}

/// NAN-1346 #3: shapes that cannot be column-aligned (aggregated main + raw-event
/// subsearch) must fail generation with an actionable message, not reach ClickHouse
/// and die with a bare Code 53 TYPE_MISMATCH.
#[test]
fn append_mismatched_shapes_error_actionably() {
    let query = parse_query("* | stats count() by src_endpoint.ip | append [search class_uid=3002]")
        .expect("query must parse");
    let gen = ClickHouseSqlGenerator::with_table("nanosiem.ocsf_logs".to_string())
        .with_profile(Arc::new(OcsfProfile::new()));
    let err = gen
        .generate(&query, &fixture_time_range())
        .expect_err("misaligned append shapes must be a generation error");
    assert!(
        err.to_string().contains("append"),
        "error must explain the append shape mismatch; got: {err}"
    );
}

/// NAN-1346 #3: append arms can union a numeric column with an eval'd string under
/// the same name (e.g. `… by class_uid | append […| eval class_uid = "ALL"]`),
/// producing a Variant-typed column. ClickHouse rejects ORDER BY/GROUP BY on
/// Variant by default (Code 44) — append queries opt in.
#[test]
fn append_queries_allow_variant_order_and_group_by() {
    let sql = ocsf_sql(
        r#"* | stats count() as events by class_uid | append [search * | stats count() as events | eval class_uid = "ALL"] | sort class_uid"#,
        "nanosiem",
    );
    assert!(
        sql.contains("allow_suspicious_types_in_order_by=1"),
        "append queries must allow Variant ORDER BY (NAN-1346 #3); SQL:\n{sql}"
    );
}

/// NAN-1346 #3 (UDM parity): the name-aligned NULL padding applies identically under
/// the UDM profile — `append` of two stats with different group-bys was equally
/// broken there (Code 53).
#[test]
fn append_null_padding_applies_under_udm_profile() {
    use nanosiem_core::schema::UdmProfile;
    let query = parse_query("* | stats count by src_ip | append [search * | stats count by dest_ip]")
        .expect("query must parse");
    let gen = ClickHouseSqlGenerator::with_table("nanosiem.logs".to_string())
        .with_profile(Arc::new(UdmProfile::new()));
    let sql = gen
        .generate(&query, &fixture_time_range())
        .expect("UDM append must generate");
    assert!(
        sql.contains("NULL AS dest_ip") && sql.contains("NULL AS src_ip"),
        "UDM append arms must NULL-pad by name (NAN-1346 #3); SQL:\n{sql}"
    );
}

async fn exec(client: &reqwest::Client, sql: &str) -> Result<String, String> {
    let resp = client
        .post(ch_url())
        .basic_auth(ch_user(), Some(ch_pass()))
        .body(sql.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("HTTP {status}: {body}"))
    }
}

async fn reachable(client: &reqwest::Client) -> bool {
    exec(client, "SELECT 1")
        .await
        .map(|b| b.trim() == "1")
        .unwrap_or(false)
}

/// Insert one OCSF event (the `event` column only — the client contract).
async fn insert_event(client: &reqwest::Client, db: &str, event_json: &str) -> Result<(), String> {
    let stmt = format!("INSERT INTO {db}.ocsf_logs (event) FORMAT JSONEachRow").replace(' ', "%20");
    let url = format!("{}/?query={stmt}&async_insert=0&wait_end_of_query=1", ch_url());
    let row = serde_json::json!({ "event": serde_json::from_str::<Value>(event_json).unwrap() })
        .to_string();
    let resp = client
        .post(url)
        .basic_auth(ch_user(), Some(ch_pass()))
        .body(row)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {status}: {body}"))
    }
}

/// Strip CREATE DATABASE + TTL and repoint at the throwaway DB.
fn test_table_ddl(db: &str) -> String {
    // NAN-1241: extract ONLY the ocsf_logs CREATE TABLE — the canonical DDL is
    // multi-statement (prevalence MVs/dicts) and the CH HTTP endpoint rejects
    // multi-statement bodies. Strip `--` comments + the TTL clause.
    let start = DDL
        .find("CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs")
        .expect("ocsf_logs CREATE TABLE in DDL");
    let no_comments: String = DDL[start..]
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let end = no_comments.find(';').expect("CREATE TABLE terminator");
    no_comments[..end]
        .lines()
        .filter(|l| !l.trim_start().starts_with("TTL "))
        .collect::<Vec<_>>()
        .join("\n")
        .replace("nanosiem.ocsf_logs", &format!("{db}.ocsf_logs"))
}

/// Run an nPL query that ends in `| stats count` (or `count by`) and return the
/// single scalar `count` (the first/only count cell). Panics with the generated
/// SQL on CH error so a resolution regression is debuggable.
async fn count(client: &reqwest::Client, db: &str, npl: &str) -> u64 {
    let sql = format!("{} FORMAT TSV", ocsf_sql(npl, db));
    let body = exec(client, &sql)
        .await
        .unwrap_or_else(|e| panic!("CH error for nPL `{npl}`:\n{sql}\n\n{e}"));
    body.trim()
        .lines()
        .next()
        .and_then(|l| l.split('\t').last())
        .and_then(|c| c.trim().parse().ok())
        .unwrap_or_else(|| panic!("could not parse count from `{body}` for `{npl}`"))
}

// NAN-1262: flaky in this reqwest fixture harness — a PREWHERE query run
// immediately after the per-fixture inserts intermittently returns 0 rows (0-vs-4)
// in-process, while the *identical* generated SQL returns the correct count
// standalone (curl) AND the live search service returns correct counts against
// real OCSF data. Root cause is an insert-visibility quirk of the harness, NOT the
// product. Ignored until the harness is made deterministic (batch insert / settle);
// the OCSF query path itself is covered by ocsf_byfield_resolution + live validation.
#[ignore = "NAN-1262: harness insert-visibility flakiness; product path validated separately"]
#[tokio::test]
async fn ocsf_npl_queries_execute_against_fixtures() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return;
    }
    let client = reqwest::Client::new();
    if !reachable(&client).await {
        eprintln!(
            "Skipping: ClickHouse not reachable at {} as admin (start: docker-compose up -d clickhouse)",
            ch_url()
        );
        return;
    }

    let db = format!(
        "ocsf_query_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    exec(&client, &format!("CREATE DATABASE {db}"))
        .await
        .expect("create test db");

    let result = run_assertions(&client, &db).await;
    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    result.expect("ocsf query assertions");
}

async fn run_assertions(client: &reqwest::Client, db: &str) -> Result<(), String> {
    exec(client, &test_table_ddl(db)).await?;
    for (name, raw) in FIXTURES {
        insert_event(client, db, raw)
            .await
            .map_err(|e| format!("insert {name}: {e}"))?;
    }

    // Sanity: all six fixtures landed.
    let total = count(client, db, "* | stats count").await;
    if total != 6 {
        return Err(format!("expected 6 fixtures, got {total}"));
    }

    // 1) Full-text keyword on `message`. Only the process fixture's message
    //    contains "powershell".
    let kw = count(client, db, "powershell | stats count").await;
    if kw != 1 {
        return Err(format!("keyword `powershell` count = {kw}, expected 1"));
    }
    // A keyword absent from every message returns nothing.
    let kw_none = count(client, db, "thiswordappearsnowhere | stats count").await;
    if kw_none != 0 {
        return Err(format!("keyword miss count = {kw_none}, expected 0"));
    }

    // 2) Promoted dotted column → quoted indexed `"src_endpoint.ip"` column.
    //    10.20.30.40 is the initiator on auth + network + dns + http (4 events);
    //    the process/file fixtures have no src_endpoint.
    let ip = count(
        client,
        db,
        "src_endpoint.ip=\"10.20.30.40\" | stats count",
    )
    .await;
    if ip != 4 {
        return Err(format!(
            "src_endpoint.ip=10.20.30.40 count = {ip}, expected 4 (auth+network+dns+http)"
        ));
    }

    // 3) stats count BY a promoted dotted column. src_endpoint.ip groups:
    //    '' (process+file = 2), '10.20.30.40' (4). The query returns one row per
    //    distinct ip; assert the 10.20.30.40 group has count 4.
    let by_ip_sql = format!(
        "{} FORMAT TSV",
        ocsf_sql("* | stats count by src_endpoint.ip", db)
    );
    let by_ip = exec(client, &by_ip_sql)
        .await
        .map_err(|e| format!("stats-by failed:\n{by_ip_sql}\n{e}"))?;
    let hot = by_ip
        .lines()
        .find(|l| l.starts_with("10.20.30.40\t"))
        .and_then(|l| l.split('\t').nth(1))
        .and_then(|c| c.trim().parse::<u64>().ok());
    if hot != Some(4) {
        return Err(format!(
            "stats count by src_endpoint.ip: 10.20.30.40 group = {hot:?}, expected Some(4)\nrows:\n{by_ip}"
        ));
    }

    // 4) Promoted enrichment field (dual-mode geo). location.country is the ISO
    //    code; only the http fixture carries src_endpoint.location.country = "US".
    let geo = count(
        client,
        db,
        "src_endpoint.location.country=US | stats count",
    )
    .await;
    if geo != 1 {
        return Err(format!(
            "src_endpoint.location.country=US count = {geo}, expected 1 (http)"
        ));
    }

    // 5) Unpromoted TAIL field via JsonPath. actor.process.parent_process.name
    //    is NOT a promoted column (only its .cmd_line sibling is) → resolves to
    //    JSONExtractString(event, 'actor','process','parent_process','name').
    //    Only the process fixture has actor.process.parent_process.name =
    //    "userinit.exe".
    let tail_sql = ocsf_sql(
        "actor.process.parent_process.name=\"userinit.exe\" | stats count",
        db,
    );
    if !tail_sql.contains("JSONExtractString(event, 'actor', 'process', 'parent_process', 'name')") {
        return Err(format!(
            "tail field did not resolve to JSONExtract(event,…); SQL:\n{tail_sql}"
        ));
    }
    let tail = count(
        client,
        db,
        "actor.process.parent_process.name=\"userinit.exe\" | stats count",
    )
    .await;
    if tail != 1 {
        return Err(format!(
            "tail actor.process.parent_process.name=userinit.exe count = {tail}, expected 1 (process)"
        ));
    }
    // A tail value that exists in no event matches nothing (guards the
    // silent-empty failure mode JsonPath invites).
    let tail_none = count(
        client,
        db,
        "actor.process.parent_process.name=\"no_such_parent.exe\" | stats count",
    )
    .await;
    if tail_none != 0 {
        return Err(format!("tail miss count = {tail_none}, expected 0"));
    }

    // 6) Taxonomy int. class_uid=3002 is the single Authentication event.
    let auth = count(client, db, "class_uid=3002 | stats count").await;
    if auth != 1 {
        return Err(format!("class_uid=3002 count = {auth}, expected 1 (auth)"));
    }
    // class_uid grouping: each of the six fixtures is a distinct class, so every
    // group has count 1 and there are six groups.
    let by_class_sql = format!("{} FORMAT TSV", ocsf_sql("* | stats count by class_uid", db));
    let by_class = exec(client, &by_class_sql)
        .await
        .map_err(|e| format!("stats by class_uid failed:\n{by_class_sql}\n{e}"))?;
    let groups = by_class.trim().lines().count();
    if groups != 6 {
        return Err(format!(
            "stats count by class_uid: {groups} groups, expected 6\n{by_class}"
        ));
    }

    // 7) append (NAN-1346 #3): name-aligned NULL-padded UNION executes. Main arm
    //    groups by src_endpoint.ip ('' ×2 + 10.20.30.40 ×4 → 2 rows), appended arm
    //    by dst_endpoint.ip ('' ×2 + 192.0.2.50 + 10.0.0.53 + 93.184.216.34 + a
    //    NATted dst → varies); assert the union returns main rows + sub rows with
    //    both columns present (padding makes the row count the sum of both arms).
    let append_sql = format!(
        "{} FORMAT TSV",
        ocsf_sql(
            "* | stats count() as events by src_endpoint.ip | append [search * | stats count() as events by dst_endpoint.ip]",
            db
        )
    );
    let append_out = exec(client, &append_sql)
        .await
        .map_err(|e| format!("append union failed:\n{append_sql}\n{e}"))?;
    let append_rows = append_out.trim().lines().count();
    if append_rows < 4 {
        return Err(format!(
            "append union returned {append_rows} rows, expected ≥4 (2 src groups + ≥2 dst groups)\n{append_out}"
        ));
    }

    Ok(())
}

/// NAN-1346 #5 regression (pure SQL-gen, no DB): the `tree process` preset's
/// UDM process-lineage fields must resolve through the profile and alias back
/// to their nPL names (the tree builder reads result rows by those names).
/// `parent_process_guid` maps to the promoted parent/initiator uid
/// (`actor.process.uid`, manifest udm_field); class-split concepts
/// (process_guid/process_name/…) project their unified columns. Before the
/// fix the raw UDM identifiers were emitted and 500'd with Code 47.
#[test]
fn tree_process_preset_lineage_resolves_under_ocsf() {
    let sql = ocsf_sql("* | tree process", "nanosiem");
    assert!(
        sql.contains(r#""actor.process.uid" AS parent_process_guid"#),
        "parent_process_guid must resolve to the OCSF parent uid (NAN-1346 #5); SQL:\n{sql}"
    );
    assert!(
        sql.contains("process_guid_unified AS process_guid"),
        "process_guid must project its unified column aliased back (NAN-1346 #5); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("SELECT *, parent_process_guid")
            && !sql.contains(", parent_process_guid,"),
        "the raw UDM lineage identifier must not be emitted under OCSF; SQL:\n{sql}"
    );
}

/// NAN-1346 #5 regression (pure SQL-gen, no DB): a resolve_identity on a field
/// that is unpromoted under OCSF (`dest_user` has no manifest mapping) resolves
/// to a JSONExtract EXPRESSION — qualifying that with `main.` produced
/// `main.JSONExtractString(…)`, which ClickHouse rejects as an unknown function
/// (Code 46). Expressions are used unqualified (their inner `event` refs bind
/// to main; the joined identity table carries no event columns).
#[test]
fn resolve_identity_on_unpromoted_field_does_not_qualify_expressions() {
    let sql = ocsf_sql("* | resolve_identity field=dest_user", "nanosiem");
    assert!(
        !sql.contains("main.JSONExtract"),
        "JSONExtract expressions must not be main.-qualified (NAN-1346 #5); SQL:\n{sql}"
    );
}

/// NAN-1339 follow-up (pure SQL-gen, no DB): UDM `dest_user` must resolve to the
/// promoted OCSF target-account column. Per OCSF Authentication 3002, `user` is
/// the TARGET/subject account and `actor.user` the initiator — exactly UDM
/// dest_user/src_user (`src_user` → `actor.user.name` was already mapped).
/// Before the manifest entry, `dest_user` fell through to
/// `JSONExtractString(event, 'dest_user')` — a key OCSF never carries — so
/// searches/stats/resolve_identity on it silently matched nothing.
#[test]
fn dest_user_resolves_to_promoted_target_account_column() {
    let sql = ocsf_sql(r#"dest_user="admin" | stats count() by dest_user"#, "nanosiem");
    assert!(
        sql.contains(r#""user.name""#),
        "dest_user must resolve to the promoted user.name column (NAN-1339); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("event, 'dest_user'"),
        "dest_user must not fall through to the event tail (NAN-1339); SQL:\n{sql}"
    );
}
