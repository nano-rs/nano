// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4918: `vendor_risk_score` / `vendor_risk_level` read the producer's
//! OCSF `event.risk_score` / `event.risk_level` on the OCSF profile; the bare
//! `risk_score` / `risk_level` stay owned by risk-based alerting (the
//! `unmapped` spill the finding writer fills).
//!
//! The SQL-shape tests are pure. The live test runs the generated SQL on a
//! disposable ClickHouse through the shared transport:
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --test ocsf_vendor_risk_alias -- --ignored
//! ```

use std::sync::Arc;

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::{FieldType, OcsfProfile, SchemaProfile};

/// Projection / aggregation form (absent reads as 0, as for every numeric
/// JSON projection).
const NUMERIC_EVENT_RISK: &str = r#"coalesce(accurateCastOrNull(event."risk_score", 'Float64'), 0.)"#;
/// Predicate form: absent or malformed stays NULL, so it never matches.
const PREDICATE_EVENT_RISK: &str = r#"accurateCastOrNull(event."risk_score", 'Float64')"#;

fn tr() -> TimeRange {
    TimeRange {
        start: "2026-11-01T00:00:00Z".parse().unwrap(),
        end: "2026-11-04T00:00:00Z".parse().unwrap(),
    }
}

fn sql_for(npl: &str, table: &str) -> String {
    let query = parse_query(npl).unwrap_or_else(|e| panic!("parse {npl}: {e}"));
    ClickHouseSqlGenerator::with_table(table)
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&query, &tr())
        .unwrap_or_else(|e| panic!("gen {npl}: {e}"))
}

#[test]
fn vendor_aliases_resolve_like_the_event_prefix() {
    let p = OcsfProfile::new();
    assert_eq!(p.resolve("vendor_risk_score"), p.resolve("event.risk_score"));
    assert_eq!(p.resolve("vendor_risk_level"), p.resolve("event.risk_level"));
    assert_ne!(p.resolve("vendor_risk_score"), p.resolve("risk_score"));
    assert!(p.is_known_field("vendor_risk_score") && p.is_known_field("vendor_risk_level"));
    // The contract types the attribute (integer_t / string_t); RBA's bare
    // `risk_score` keeps its Float typing.
    assert_eq!(p.field_type("vendor_risk_score"), Some(FieldType::Integer));
    assert_eq!(p.field_type("event.risk_score"), Some(FieldType::Integer));
    assert_eq!(p.field_type("vendor_risk_level"), Some(FieldType::String));
    assert_eq!(p.field_type("risk_score"), Some(FieldType::Float));
}

#[test]
fn vendor_risk_score_compares_numerically_on_event_json() {
    let sql = sql_for("vendor_risk_score > 50", "nanosiem.ocsf_logs");
    assert!(sql.contains(&format!("({PREDICATE_EVENT_RISK} > 50)")) && !sql.contains("coalesce("), "{sql}");
    assert!(!sql.contains(r#"unmapped."risk_score""#), "{sql}");
    // `event.risk_score` emits the identical predicate.
    let explicit = sql_for("event.risk_score > 50", "nanosiem.ocsf_logs");
    assert!(explicit.contains(&format!("({PREDICATE_EVENT_RISK} > 50)")) && !explicit.contains("coalesce("), "{explicit}");
}

#[test]
fn vendor_risk_level_reads_event_and_bare_names_stay_rba() {
    let sql = sql_for(r#"vendor_risk_level="High""#, "nanosiem.ocsf_logs");
    assert!(sql.contains(r#"lower(multiIf(isNotNull(event."risk_level")"#) && sql.contains("= 'high'"), "{sql}");
    assert!(!sql.contains(r#"unmapped."risk_level""#), "{sql}");

    let sql = sql_for(r#"risk_level="high" risk_score > 50"#, "nanosiem.ocsf_logs");
    assert!(sql.contains(r#"unmapped."risk_level""#), "{sql}");
    assert!(
        sql.contains(r#"accurateCastOrNull(unmapped."risk_score", 'Float64') > 50"#)
            && !sql.contains(r#"coalesce(accurateCastOrNull(unmapped."risk_score""#),
        "{sql}"
    );
    assert!(!sql.contains(r#"event."risk_"#), "{sql}");
}

#[test]
fn vendor_aliases_survive_where_table_and_stats_stages() {
    let sql = sql_for(
        r#"class_uid=2004 | where vendor_risk_score >= 70 | table vendor_risk_level, vendor_risk_score"#,
        "nanosiem.ocsf_logs",
    );
    assert!(sql.contains(&format!("WHERE {PREDICATE_EVENT_RISK} >= 70")), "{sql}");
    assert!(sql.contains(&format!("{NUMERIC_EVENT_RISK} AS vendor_risk_score")), "{sql}");

    // stage_0 computes the numeric extractor once; the aggregation reads that
    // alias instead of re-deriving it from `event` (NAN-4934).
    let sql = sql_for("* | stats max(vendor_risk_score) by vendor_risk_level", "nanosiem.ocsf_logs");
    assert!(
        sql.contains(&format!("{NUMERIC_EVENT_RISK} AS vendor_risk_score"))
            && sql.contains("max(vendor_risk_score)"),
        "{sql}"
    );
}

#[test]
fn only_comparisons_switch_to_the_numeric_extractor() {
    // Ordered comparisons and IN lists compare numbers.
    let sql = sql_for("vendor_risk_score IN (87, 90)", "t");
    assert!(sql.contains(&format!("({PREDICATE_EVENT_RISK} IN (87, 90))")), "{sql}");
    let sql = sql_for("vendor_risk_score != 5", "t");
    assert!(sql.contains(&format!("({PREDICATE_EVENT_RISK} != 5)")), "{sql}");
    // Non-numeric literals are refused, never mapped to 0.
    for q in [r#"vendor_risk_score IN (87, "high")"#, r#"vendor_risk_score NOT IN ("x")"#] {
        let query = parse_query(q).unwrap();
        let err = ClickHouseSqlGenerator::with_table("t")
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&query, &tr())
            .unwrap_err();
        assert!(err.to_string().contains("numeric IN values"), "{q}: {err}");
    }
    // Regex / CONTAINS / wildcards / existence keep the String extractor:
    // `match()` on a Float64 is a ClickHouse type error.
    for q in [r#"vendor_risk_score=/8.*/"#, r#"vendor_risk_score CONTAINS "8""#, r#"vendor_risk_score="8*""#, "vendor_risk_score=*"] {
        let sql = sql_for(q, "t");
        assert!(!sql.contains("accurateCastOrNull"), "{q}: {sql}");
    }
}

// ---------------------------------------------------------------------------
// Live ClickHouse (shared transport: pins LZ4, required on CH 26.9+)
// ---------------------------------------------------------------------------

fn ch() -> clickhouse::Client {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    let mut client = nanosiem_core::db::clickhouse_transport::client().with_url(url);
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        client = client.with_password(password);
    }
    client
}

async fn messages(ch: &clickhouse::Client, table: &str, npl: &str) -> Vec<String> {
    let sql = sql_for(npl, table);
    // clickhouse-rs treats `?` as a bind placeholder; `??` is a literal `?`
    // (the generated regex carries `(?i)`).
    let wrapped = format!("SELECT message FROM ({}) ORDER BY message", sql.split(" SETTINGS ").next().unwrap())
        .replace('?', "??");
    ch.query(&wrapped)
        .fetch_all::<String>()
        .await
        .unwrap_or_else(|e| panic!("{npl}: {e}\n--- SQL ---\n{wrapped}"))
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn vendor_and_rba_risk_names_select_different_rows_on_clickhouse() {
    let ch = ch();
    let db = format!("nan4918_vendor_risk_{}", uuid::Uuid::now_v7().simple());
    let table = format!("{db}.ocsf_logs");
    ch.query(&format!("CREATE DATABASE {db}")).execute().await.unwrap();
    // The columns the generated SQL reads; `event` and `unmapped` are the same
    // JSON columns `ocsf_logs` carries. A wide `| where` stage re-adds the
    // derived columns `SELECT *` omits, so they exist here as empty aliases.
    let derived = [
        "prevalence_file_hash", "prevalence_process_hash", "prevalence_dest_domain",
        "prevalence_dest_ip", "prevalence_min", "activity", "trace_id", "span_id",
        "process_name_unified", "process_path_unified", "command_line_unified",
        "process_id_unified", "process_guid_unified", "process_hash_unified",
        "user_unified", "url_domain_unified", "url_unified", "src_host_unified",
    ]
    .iter()
    .map(|c| format!(", {c} String ALIAS ''"))
    .collect::<String>();
    ch.query(&format!(
        "CREATE TABLE {table} (
            id UUID DEFAULT generateUUIDv7(),
            timestamp DateTime64(3),
            source_type LowCardinality(String),
            message String,
            event JSON,
            unmapped JSON{derived}
        ) ENGINE = MergeTree ORDER BY timestamp"
    ))
    .execute()
    .await
    .unwrap();
    // `vendor-high`: the producer says 87/High, RBA scored it 5/low.
    // `rba-high`: the producer says 12/Low, RBA scored it 90/high.
    ch.query(&format!(
        r#"INSERT INTO {table} (timestamp, source_type, message, event, unmapped) VALUES
        ('2026-11-02 10:00:00', 'edr', 'vendor-high', '{{"risk_score": 87, "risk_level": "High"}}', '{{"risk_score": 5, "risk_level": "low"}}'),
        ('2026-11-02 11:00:00', 'edr', 'rba-high', '{{"risk_score": 12, "risk_level": "Low"}}', '{{"risk_score": 90, "risk_level": "high"}}'),
        ('2026-11-02 12:00:00', 'edr', 'no-score', '{{"activity_id": 1}}', '{{"other": 1}}'),
        ('2026-11-02 13:00:00', 'edr', 'malformed', '{{"risk_score": "n/a"}}', '{{}}')"#
    ))
    .execute()
    .await
    .unwrap();

    let result = async {
        assert_eq!(messages(&ch, &table, "vendor_risk_score > 50 | table message").await, ["vendor-high"]);
        assert_eq!(messages(&ch, &table, "event.risk_score > 50 | table message").await, ["vendor-high"]);
        assert_eq!(messages(&ch, &table, "risk_score > 50 | table message").await, ["rba-high"]);
        assert_eq!(messages(&ch, &table, r#"vendor_risk_level="high" | table message"#).await, ["vendor-high"]);
        assert_eq!(messages(&ch, &table, r#"risk_level="high" | table message"#).await, ["rba-high"]);
        assert_eq!(messages(&ch, &table, "vendor_risk_score IN (87, 1) | table message").await, ["vendor-high"]);
        // NAN-4918 codex P1: rows without the attribute (`no-score`) or with a
        // non-numeric value (`malformed`) match NO numeric predicate.
        let both = ["rba-high", "vendor-high"];
        for (q, want) in [
            ("vendor_risk_score < 50", &["rba-high"][..]),
            ("vendor_risk_score <= 0", &[][..]),
            ("vendor_risk_score != 87", &["rba-high"][..]),
            ("vendor_risk_score = 0", &[][..]),
            ("vendor_risk_score IN (87)", &["vendor-high"][..]),
            ("vendor_risk_score NOT IN (87)", &["rba-high"][..]),
            ("vendor_risk_score IN (0)", &[][..]),
            ("vendor_risk_score NOT IN (0)", &both[..]),
            ("risk_score != 5", &["rba-high"][..]),
            ("* | where vendor_risk_score != 87", &["rba-high"][..]),
            ("* | where vendor_risk_score < 50", &["rba-high"][..]),
            ("* | where vendor_risk_score NOT IN (87)", &["rba-high"][..]),
            ("* | where vendor_risk_score IN (0)", &[][..]),
        ] {
            let got = messages(&ch, &table, &format!("{q} | table message")).await;
            assert_eq!(got, want, "{q}");
        }
        assert_eq!(messages(&ch, &table, "vendor_risk_score=/^8/ | table message").await, ["vendor-high"]);
        assert_eq!(messages(&ch, &table, r#"vendor_risk_score CONTAINS "2" | table message"#).await, ["rba-high"]);
        let sql = sql_for("* | stats max(vendor_risk_score) as m", &table);
        let max = ch
            .query(&format!("SELECT assumeNotNull(m) FROM ({})", sql.split(" SETTINGS ").next().unwrap()))
            .fetch_one::<f64>()
            .await
            .unwrap_or_else(|e| panic!("{e}\n{sql}"));
        assert_eq!(max, 87.0);
    };
    // Drop the throwaway database even when an assertion fails.
    let res = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(result)).await;
    ch.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await.unwrap();
    if let Err(panic) = res {
        std::panic::resume_unwind(panic);
    }
}

