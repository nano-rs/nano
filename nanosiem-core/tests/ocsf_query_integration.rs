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
        sql.contains("JSONExtractString(unmapped, 'request.method')"),
        "spath must extract from the OCSF tail column `unmapped` (NAN-1343/1443); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("JSONExtractString(ext,"),
        "spath must not reference the nonexistent OCSF `ext` column (NAN-1343); SQL:\n{sql}"
    );
}

/// NAN-1388 regression (pure SQL-gen, no DB / parity gap G14): UDM-muscle-memory
/// `ext.foo` search terms must strip-and-remap to the OCSF spill location
/// `unmapped.foo`. Before the fix the resolve fallback JSONExtract'd a top-level
/// `ext` key that never exists in an OCSF event → silently 0 rows
/// (`ext.error_code` = 0 vs `unmapped.error_code` = 23,117 on demo data), while
/// `spath input=ext` WAS remapped (#2043) — a half-fixed inconsistency.
#[test]
fn ext_prefix_remaps_to_unmapped_under_ocsf() {
    // String compare → native subcolumn access against unmapped.* (NAN-1426;
    // previously JSONExtractString, which re-serialized the whole event per row).
    let sql = ocsf_sql(r#"ext.cache_status="hit""#, "nanosiem");
    assert!(
        sql.contains(r#"multiIf(isNotNull(unmapped."cache_status")"#),
        "ext.* must remap to the `unmapped` spill column with a relative path (NAN-1388/1443) via subcolumn access (NAN-1426); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("'ext'"),
        "no top-level 'ext' key exists in an OCSF event (NAN-1388); SQL:\n{sql}"
    );
    // Numeric compare → nullable subcolumn cast, same remap (NAN-1426;
    // NAN-4918: a missing or non-numeric key is NULL and never matches).
    let sql = ocsf_sql("ext.sysmon_event_id=7", "nanosiem");
    assert!(
        sql.contains(r#"(accurateCastOrNull(unmapped."sysmon_event_id", 'Float64') = 7)"#)
            && !sql.contains(r#"coalesce(accurateCastOrNull(unmapped."sysmon_event_id""#),
        "numeric ext.* compare must remap + use the nullable subcolumn cast; SQL:\n{sql}"
    );
    // NEGATED compare: the multiIf subcolumn form returns '' (not NULL) for
    // rows missing the key, so `!= 'hit'` keeps them — negation must not
    // silently drop the no-key rows (the toString-NULL trap from NAN-1161
    // does not apply here; parity verified vs the old extractor on local CH).
    let sql = ocsf_sql(r#"ext.cache_status!="hit""#, "nanosiem");
    assert!(
        sql.contains(r#"lower(toString(multiIf(isNotNull(unmapped."cache_status")"#)
            && sql.contains("!= 'hit'"),
        "negated ext.* compare must use the ''-returning subcolumn form; SQL:\n{sql}"
    );
}

/// NAN-1388 regression (pure SQL-gen, no DB / parity gap G14): `event.foo` names
/// the OCSF JSON tail column explicitly — strip the prefix and resolve the rest,
/// landing on the promoted column when one exists, else the `event` tail. Before
/// the fix it JSONExtract'd a top-level `event` key that never exists.
#[test]
fn event_prefix_strips_to_event_tail_under_ocsf() {
    // Unpromoted OCSF attribute → stripped JsonPath into the stored `event`
    // JSON (NAN-4903: the registry knows every OCSF attribute, so it reads the
    // `event` subcolumn, not the vendor `unmapped` spill).
    let sql = ocsf_sql(
        r#"event.actor.process.parent_process.name="userinit.exe""#,
        "nanosiem",
    );
    assert!(
        sql.contains(
            r#"multiIf(isNotNull(event."actor"."process"."parent_process"."name")"#
        ),
        "event.<OCSF attribute> must strip to the `event` JSON subcolumn (NAN-4903, NAN-1426); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("'event'"),
        "no top-level 'event' key exists in an OCSF event (NAN-1388); SQL:\n{sql}"
    );
    // Promoted attribute → the indexed promoted column (same value, faster).
    // Raw equality, not lower()-wrapped: src_endpoint.ip is lowercased at
    // ingest, and the raw form is what engages its bloom index (NAN-1412).
    let sql = ocsf_sql(r#"event.src_endpoint.ip="10.20.30.40""#, "nanosiem");
    assert!(
        sql.contains(r#""src_endpoint.ip" = '10.20.30.40'"#)
            && !sql.contains(r#"lower("src_endpoint.ip")"#),
        "event.<promoted> must land on the promoted column, raw-compared (NAN-1388/NAN-1412); SQL:\n{sql}"
    );
}

/// NAN-1388 UDM-unchanged proof (pure SQL-gen, no DB): the remap lives in
/// `OcsfProfile::resolve` only — under UDM `ext.*` never resolves to OCSF's
/// `unmapped.*` spill. NAN-1411 updated the pinned emission: the explicit
/// `ext.foo` spelling now strips its prefix and probes the same `ext.foo`
/// access as the unprefixed fallthrough (it used to be mangled into
/// `ext.extfoo` — dot deleted by `sanitize_json_path` — silently 0 rows).
/// `event.*` carries no special meaning under UDM and keeps the old emission.
#[test]
fn ext_prefix_udm_sql_unchanged() {
    use nanosiem_core::schema::UdmProfile;
    let udm_sql = |npl: &str| {
        let query = parse_query(npl).unwrap();
        ClickHouseSqlGenerator::with_table("nanosiem.logs")
            .with_profile(Arc::new(UdmProfile::new()))
            .generate(&query, &fixture_time_range())
            .unwrap()
    };
    let sql = udm_sql(r#"ext.cache_status="hit""#);
    assert!(
        sql.contains("(lower(toString(ext.cache_status)) = 'hit')"),
        "UDM ext.* must probe the real ext key (NAN-1411); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("unmapped"),
        "no OCSF remap leakage into UDM (NAN-1388); SQL:\n{sql}"
    );
    let sql = udm_sql(r#"event.foo="x""#);
    assert!(
        sql.contains("(lower(toString(ext.eventfoo)) = 'x')"),
        "UDM event.* emission must stay byte-identical (NAN-1388); SQL:\n{sql}"
    );
}

/// NAN-1382 regression (pure SQL-gen, no DB / parity gap G6): a UDM verb-valued
/// predicate whose resolved OCSF column is an enum-encoded INT must translate the
/// verb via the manifest enum metadata instead of emitting the dead
/// `lower(toString(<int col>)) = 'verb'` (which matched 0 of 127,209
/// `status_id = 2` rows on local data). Fixed label tables (status_id,
/// auth_protocol_id, severity_id) compare the indexed int; numeric strings pass
/// through as the id; both the UDM alias and the native column spelling resolve.
#[test]
fn enum_verb_predicates_translate_to_enum_ints_under_ocsf() {
    // Eq via the UDM alias → indexed int compare.
    let sql = ocsf_sql(r#"auth_result="failure""#, "nanosiem");
    assert!(
        sql.contains("status_id = 2"),
        "auth_result=\"failure\" must compare status_id = 2 (NAN-1382); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("lower(toString(status_id))"),
        "the dead string compare on the enum int must be gone (NAN-1382); SQL:\n{sql}"
    );
    // Ne (negation keeps absent/unknown rows: 0 != 2).
    let sql = ocsf_sql(r#"auth_result!="failure""#, "nanosiem");
    assert!(
        sql.contains("status_id != 2"),
        "auth_result!=\"failure\" must compare status_id != 2 (NAN-1382); SQL:\n{sql}"
    );
    // IN list routes through the column branch (it previously fell to the
    // metadata-JSON branch: `JSONExtractString(metadata, 'auth_result')`).
    let sql = ocsf_sql(r#"auth_result IN ("failure", "success")"#, "nanosiem");
    assert!(
        sql.contains("status_id IN (2, 1)"),
        "auth_result IN (...) must translate every verb (NAN-1382); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("JSONExtractString(metadata"),
        "enum alias IN must not fall to the metadata-JSON branch (NAN-1382); SQL:\n{sql}"
    );
    // auth_type → auth_protocol_id fixed table.
    let sql = ocsf_sql(r#"auth_type="kerberos""#, "nanosiem");
    assert!(
        sql.contains("auth_protocol_id = 2"),
        "auth_type=\"kerberos\" must compare auth_protocol_id = 2 (NAN-1382); SQL:\n{sql}"
    );
    // Native column spelling translates too, and the filter never emits the
    // type-error form `lower(severity_id) = 'high'` (CH Code 43 pre-fix).
    let sql = ocsf_sql(r#"severity_id="high""#, "nanosiem");
    assert!(
        sql.contains("severity_id = 4"),
        "severity_id=\"high\" must compare severity_id = 4 (NAN-1382); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("lower(severity_id)"),
        "must not lower() the enum int column (CH Code 43, NAN-1382); SQL:\n{sql}"
    );
    // Numeric string (UI drilldown) passes through as the id.
    let sql = ocsf_sql(r#"auth_result="2""#, "nanosiem");
    assert!(
        sql.contains("status_id = 2"),
        "a numeric string must pass through as the enum id (NAN-1382); SQL:\n{sql}"
    );
}

/// NAN-1382 (G6): a verb OUTSIDE a fixed enum table fails LOUDLY with the valid
/// labels — never a silent zero-match.
#[test]
fn enum_verb_unknown_label_fails_loudly_under_ocsf() {
    let query = parse_query(r#"auth_result="bogus""#).unwrap();
    let gen = ClickHouseSqlGenerator::with_table("nanosiem.ocsf_logs".to_string())
        .with_profile(Arc::new(OcsfProfile::new()));
    let err = gen
        .generate(&query, &fixture_time_range())
        .expect_err("an unknown enum label must be a loud validation error (NAN-1382)");
    let msg = err.to_string();
    assert!(
        msg.contains("not a valid value") && msg.contains("failure"),
        "error must name the field's valid labels (NAN-1382); got: {msg}"
    );
}

/// NAN-1382 (G6): `activity_id` is CLASS-SCOPED (1=Logon on 3002 but 1=Create on
/// 1001), so no fixed table exists — string verbs on its UDM aliases
/// (`event_type`, `file_action`) match the sibling `activity` label column
/// (manifest `enum_label_column`) instead of the int.
#[test]
fn class_scoped_enum_verbs_match_sibling_label_column_under_ocsf() {
    let sql = ocsf_sql(r#"event_type="logon""#, "nanosiem");
    assert!(
        sql.contains("lower(activity) = 'logon'"),
        "event_type=\"logon\" must match the sibling `activity` label column (NAN-1382); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("lower(activity_id)") && !sql.contains("lower(toString(activity_id))"),
        "no string ops on the class-scoped enum int (NAN-1382); SQL:\n{sql}"
    );
    let sql = ocsf_sql(r#"file_action="delete""#, "nanosiem");
    assert!(
        sql.contains("lower(activity) = 'delete'"),
        "file_action=\"delete\" must match the sibling `activity` label column (NAN-1382); SQL:\n{sql}"
    );
    // The integer id still targets the int column directly.
    let sql = ocsf_sql(r#"event_type=1"#, "nanosiem");
    assert!(
        sql.contains("activity_id = 1"),
        "an integer id must keep targeting activity_id (NAN-1382); SQL:\n{sql}"
    );
}

/// NAN-1382 UDM-safety: UDM stores verbs as STRING columns — no enum mapping
/// exists, so every UDM predicate keeps its exact pre-fix string form (verified
/// byte-identical across a 9-probe corpus during development; this locks the
/// WHERE forms).
#[test]
fn enum_verb_predicates_leave_udm_sql_unchanged() {
    use nanosiem_core::schema::{SchemaProfile, UdmProfile};
    let udm_sql = |npl: &str| {
        let query = parse_query(npl).unwrap();
        ClickHouseSqlGenerator::with_table("nanosiem.logs".to_string())
            .with_profile(Arc::new(UdmProfile::new()))
            .generate(&query, &fixture_time_range())
            .unwrap()
    };
    let sql = udm_sql(r#"auth_result="failure""#);
    assert!(
        sql.contains("AND (lower(auth_result) = 'failure')"),
        "UDM auth_result compare must stay the string form (NAN-1382); SQL:\n{sql}"
    );
    assert!(!sql.contains("status_id"), "no OCSF leakage into UDM; SQL:\n{sql}");
    let sql = udm_sql(r#"auth_result IN ("failure", "success")"#);
    assert!(
        sql.contains("lower(auth_result) IN ('failure', 'success')"),
        "UDM IN-list must stay the string form (NAN-1382); SQL:\n{sql}"
    );
    let sql = udm_sql(r#"event_type="logon""#);
    assert!(
        sql.contains("(event_type = 'logon')"),
        "UDM event_type (lowercased-at-ingest) form unchanged (NAN-1382); SQL:\n{sql}"
    );
    // And the profile itself: UDM never exposes an enum-int mapping.
    let udm = UdmProfile::new();
    for f in ["auth_result", "auth_type", "event_type", "severity", "status", "src_ip"] {
        assert!(
            udm.enum_int_mapping(f).is_none(),
            "UdmProfile must expose no enum-int mapping for {f} (NAN-1382)"
        );
    }
}

/// NAN-1383 regression (pure SQL-gen, no DB): a numeric comparison on an
/// unmapped/tail field under OCSF must emit the real typed extractor
/// `JSONExtractFloat(event, …)`. The codegen previously interpolated the value
/// type name into `JSONExtract{T}` producing `JSONExtractFloat64` — which is
/// not a ClickHouse function — so EVERY numeric comparison on a tail field
/// 400'd with UNKNOWN_FUNCTION (verified live against ocsf_logs).
#[test]
fn numeric_tail_comparison_emits_real_extractor_under_ocsf() {
    let sql = ocsf_sql("unmapped.some_num>3", "nanosiem");
    assert!(
        sql.contains(r#"(accurateCastOrNull(unmapped."some_num", 'Float64') > 3)"#)
            && !sql.contains(r#"coalesce(accurateCastOrNull(unmapped."some_num""#),
        "numeric tail comparison must use the nullable subcolumn cast (NAN-1426; \
         NAN-4918: a missing key is NULL and never matches); SQL:\n{sql}"
    );
    assert!(
        !sql.contains("JSONExtractFloat64"),
        "JSONExtractFloat64 does not exist in ClickHouse (NAN-1383); SQL:\n{sql}"
    );
}

/// NAN-1383 regression (pure SQL-gen, no DB): `prevalence_min` is a promoted
/// OCSF column now (MATERIALIZED least() of the four prevalence_* columns,
/// mirroring UDM logs.prevalence_min) — the search filter resolves the real
/// column instead of JSONExtract'ing a key the `event` does not carry, and the
/// multi-stage base CTE re-adds it (MATERIALIZED ⇒ absent from `SELECT *`) so a
/// `| where` stage can reference it bare.
#[test]
fn prevalence_min_resolves_to_promoted_column_under_ocsf() {
    // Top-level search filter: direct column comparison, no JSONExtract.
    let sql = ocsf_sql("prevalence_min<5", "nanosiem");
    assert!(
        sql.contains("(prevalence_min < 5)"),
        "prevalence_min must compare the promoted column; SQL:\n{sql}"
    );
    assert!(
        !sql.contains("JSONExtractFloat(event, 'prevalence_min')"),
        "prevalence_min must not fall through to the event tail; SQL:\n{sql}"
    );

    // Piped `| where`: stage_0 must project the MATERIALIZED column so the
    // stage_1 bare reference resolves (prevalence-gated saved content shape).
    let sql = ocsf_sql("* | where prevalence_min < 5", "nanosiem");
    let stage_1_at = sql.find("stage_1").expect("multi-stage CTE");
    assert!(
        sql[..stage_1_at].contains("prevalence_min"),
        "stage_0 must re-add the MATERIALIZED prevalence_min; SQL:\n{sql}"
    );
    assert!(
        sql.contains("WHERE prevalence_min < 5"),
        "| where must reference the projected column; SQL:\n{sql}"
    );
}

/// NAN-1383 UDM-safety: `prevalence_min` is a plain stored column on UDM `logs`
/// — both query shapes keep the bare-column comparison, byte-identical to
/// before the OCSF mapping (no least() leakage into UDM SQL).
#[test]
fn prevalence_min_udm_sql_unchanged() {
    use nanosiem_core::schema::UdmProfile;
    let udm_sql = |npl: &str| {
        let query = parse_query(npl).unwrap();
        ClickHouseSqlGenerator::with_table("nanosiem.logs".to_string())
            .with_profile(Arc::new(UdmProfile::new()))
            .generate(&query, &fixture_time_range())
            .unwrap()
    };
    let sql = udm_sql("prevalence_min<5");
    assert!(
        sql.contains("AND (prevalence_min < 5)"),
        "UDM search filter unchanged; SQL:\n{sql}"
    );
    assert!(!sql.contains("least("), "no OCSF least() leakage into UDM; SQL:\n{sql}");
    let sql = udm_sql("* | where prevalence_min < 5");
    assert!(
        sql.contains("WHERE prevalence_min < 5"),
        "UDM | where unchanged; SQL:\n{sql}"
    );
    assert!(!sql.contains("least("), "no OCSF least() leakage into UDM; SQL:\n{sql}");
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

/// NAN-1379 regression (pure SQL-gen, no DB): `enforce_non_audit_query` wraps
/// the user expression in `SearchExpr::Group` before AND-ing on the
/// `source_type != "audit"` exclusion — the shape every non-AUDIT_VIEW
/// principal's query takes on the standard API path. The selectivity check
/// (`has_selective_indexed_eq`, formerly `has_selective_prewhere`) previously
/// fell through `Group` into its `_ => false` arm, so entity-Eq equalities
/// were invisible there. Since NAN-1412 the generator emits a single WHERE
/// (no explicit PREWHERE); the Group-recursion now governs the
/// `optimize_read_in_order` toggle — assert the audit-wrapped query gets the
/// SAME settings as the bare query (read-in-order disabled for the selective
/// entity equality) under BOTH profiles, and that the entity filter itself
/// survives the wrap in the WHERE clause.
#[test]
fn audit_group_wrap_preserves_entity_selectivity_both_profiles() {
    use nanosiem_core::schema::UdmProfile;
    use nanosiem_core::search::query_processing::enforce_non_audit_query;

    fn settings_clause(sql: &str) -> &str {
        let start = sql
            .find("SETTINGS")
            .unwrap_or_else(|| panic!("no SETTINGS in SQL:\n{sql}"));
        &sql[start..]
    }

    let bare = r#"src_ip="10.0.0.5""#;
    let wrapped = enforce_non_audit_query(bare).expect("audit enforcement must rewrite");
    assert_ne!(
        wrapped, bare,
        "enforcement should inject the audit exclusion (got `{wrapped}`)"
    );

    // OCSF: the UDM alias must surface as the promoted dotted column in WHERE,
    // and the selective-entity read-in-order toggle must survive the wrap.
    let ocsf_bare = ocsf_sql(bare, "nanosiem");
    let ocsf_wrapped = ocsf_sql(&wrapped, "nanosiem");
    assert!(
        ocsf_wrapped.contains("\"src_endpoint.ip\" = '10.0.0.5'"),
        "OCSF audit-wrapped WHERE must keep the entity equality; SQL:\n{ocsf_wrapped}"
    );
    assert!(
        settings_clause(&ocsf_wrapped).contains("optimize_read_in_order=0"),
        "OCSF audit-wrapped selective equality must disable read-in-order; SQL:\n{ocsf_wrapped}"
    );
    assert_eq!(
        settings_clause(&ocsf_bare),
        settings_clause(&ocsf_wrapped),
        "Group-wrapped query must produce the same OCSF settings as unwrapped"
    );

    // UDM: identity resolution — same parity through the audit wrap.
    let udm_sql = |npl: &str| {
        let query = parse_query(npl).unwrap_or_else(|e| panic!("parse failed for `{npl}`: {e}"));
        ClickHouseSqlGenerator::with_table("nanosiem.logs".to_string())
            .with_profile(Arc::new(UdmProfile::new()))
            .generate(&query, &fixture_time_range())
            .unwrap_or_else(|e| panic!("UDM SQL gen failed for `{npl}`: {e}"))
    };
    let udm_bare = udm_sql(bare);
    let udm_wrapped = udm_sql(&wrapped);
    assert!(
        udm_wrapped.contains("src_ip = '10.0.0.5'"),
        "UDM audit-wrapped WHERE must keep the entity equality; SQL:\n{udm_wrapped}"
    );
    assert!(
        settings_clause(&udm_wrapped).contains("optimize_read_in_order=0"),
        "UDM audit-wrapped selective equality must disable read-in-order; SQL:\n{udm_wrapped}"
    );
    assert_eq!(
        settings_clause(&udm_bare),
        settings_clause(&udm_wrapped),
        "Group-wrapped query must produce the same UDM settings as unwrapped"
    );
}

/// NAN-1389 regression (pure SQL-gen, no DB): `| lookup` must be a SQL
/// pass-through stage under BOTH profiles. Lookup tables live in PostgreSQL and
/// are merged in Rust post-processing (`apply_lookup_enrichment`); the old
/// codegen emitted `LEFT JOIN lookup_<name>` against ClickHouse, where those
/// tables have never existed — so every `| lookup` query (existing table or
/// not) died with CH Code 60 UNKNOWN_TABLE masked as a generic 500.
#[test]
fn lookup_is_a_sql_passthrough_under_both_profiles() {
    use nanosiem_core::schema::UdmProfile;

    let npl = "error | lookup assets src_ip OUTPUT owner, criticality";

    let ocsf = ocsf_sql(npl, "nanosiem");
    assert!(
        !ocsf.contains("LEFT JOIN") && !ocsf.contains("lookup_assets"),
        "OCSF: lookup must not emit a ClickHouse JOIN (NAN-1389); SQL:\n{ocsf}"
    );
    assert!(
        ocsf.contains("SELECT * FROM stage_0"),
        "OCSF: lookup stage must be a pass-through; SQL:\n{ocsf}"
    );

    let query = parse_query(npl).expect("query must parse");
    let udm = ClickHouseSqlGenerator::with_table("nanosiem.logs".to_string())
        .with_profile(Arc::new(UdmProfile::new()))
        .generate(&query, &fixture_time_range())
        .expect("UDM SQL gen must succeed");
    assert!(
        !udm.contains("LEFT JOIN") && !udm.contains("lookup_assets"),
        "UDM: lookup must not emit a ClickHouse JOIN (NAN-1389); SQL:\n{udm}"
    );
    assert!(
        udm.contains("SELECT * FROM stage_0"),
        "UDM: lookup stage must be a pass-through; SQL:\n{udm}"
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
    let stmt = format!("INSERT INTO {db}.ocsf_logs_raw (event) FORMAT JSONEachRow").replace(' ', "%20");
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
fn test_table_ddl(db: &str) -> Vec<String> {
    // NAN-1443: the OCSF table is now three objects — `ocsf_logs_raw` (ENGINE=Null
    // landing table), `ocsf_logs_raw_mv` (derives the row), and `ocsf_logs`
    // (MergeTree storage; the `*_unified` columns are inline in its CREATE). They
    // are contiguous, ahead of the `CREATE OR REPLACE DICTIONARY` statements.
    // Extract that block, strip `--` comments + the TTL clause, split into the
    // individual statements (the CH HTTP endpoint rejects multi-statement bodies),
    // and repoint at the throwaway DB. Inserts go to `ocsf_logs_raw`; reads hit
    // `ocsf_logs`. `dictGet('nanosiem.…')` refs stay cross-DB to the real dicts.
    let start = DDL
        .find("CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs_raw")
        .expect("ocsf_logs_raw CREATE TABLE in DDL");
    let end = DDL[start..]
        .find("CREATE OR REPLACE DICTIONARY")
        .map(|i| start + i)
        .expect("dictionaries follow the ocsf_logs table block");
    DDL[start..end]
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => &l[..i],
            None => l,
        })
        .filter(|l| !l.trim_start().starts_with("TTL "))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(|s| s.trim().replace("nanosiem.ocsf_logs", &format!("{db}.ocsf_logs")))
        .filter(|s| !s.trim().is_empty())
        .collect()
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
    for stmt in test_table_ddl(db) {
        exec(client, &stmt).await?;
    }
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

    // 5) Unpromoted OCSF attribute. actor.process.parent_process.name is NOT a
    //    promoted column (only its .cmd_line sibling is) but it IS a standard
    //    OCSF attribute. NAN-4903 stores the whole object in `event JSON`, so it
    //    resolves to the `event` subcolumn and the process fixture (which carries
    //    it) matches — the NAN-1443 lean-storage drop is gone.
    let tail_sql = ocsf_sql(
        "actor.process.parent_process.name=\"userinit.exe\" | stats count",
        db,
    );
    if !tail_sql.contains("event.\"actor\".\"process\".\"parent_process\".\"name\"") {
        return Err(format!(
            "OCSF attribute did not resolve to the event JSON subcolumn; SQL:\n{tail_sql}"
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
            "tail actor.process.parent_process.name=userinit.exe count = {tail}, expected 1 \
             (the process fixture; every OCSF leaf is stored in `event`, NAN-4903)"
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

/// NAN-4903 (pure codegen): a case-preserving promoted array matches on the
/// lowered-array expression the DDL indexes; an ingest-lowered array matches raw;
/// an unpromoted path that crosses an OCSF array reads `event."a"[]."b"`.
#[test]
fn ocsf_array_fields_compile_to_membership() {
    let sql = ocsf_sql("observables.value=\"Needle-C2.Example.org\"", "nanosiem");
    assert!(
        sql.contains("has(arrayMap(x -> lower(x), ") && sql.contains("'needle-c2.example.org')"),
        "{sql}"
    );
    let sql = ocsf_sql("process.file.hashes.value=\"ABCDEF\"", "nanosiem");
    assert!(sql.contains("has(`process.file.hashes.value`, 'abcdef')") || sql.contains("has(\"process.file.hashes.value\", 'abcdef')"), "{sql}");
    let sql = ocsf_sql("answers.rdata=\"10.0.0.1\"", "nanosiem");
    assert!(sql.contains("has(arrayMap(x -> lower(x), "), "{sql}");
    let sql = ocsf_sql("module.file.signatures.state=\"Valid\"", "nanosiem");
    assert!(sql.contains("event.\"module\".\"file\".\"signatures\"[].\"state\""), "{sql}");
    let sql = ocsf_sql("observables.type_id=1", "nanosiem");
    assert!(sql.contains("arrayExists(x -> x = 1, "), "{sql}");
}

/// NAN-4903 (pure SQL-gen): a `| where` stage reads the CTE of the previous
/// stage, so a field that the profile reads from somewhere other than a
/// same-named column must use the resolved expression. Upstream rules filter
/// `| where metadata.log_source="windows_sysmon"` — a bare `"metadata.log_source"`
/// was CH Code 47 (it reads the `source_type` routing column).
#[test]
fn where_stage_resolves_aliases_json_paths_and_arrays_under_ocsf() {
    let sql = ocsf_sql(
        r#"class_uid=1007 | where metadata.log_source="windows_sysmon""#,
        "nanosiem",
    );
    assert!(
        !sql.contains(r#""metadata.log_source""#) && sql.contains("source_type"),
        "metadata.log_source in a where stage must read source_type; SQL:\n{sql}"
    );
    let sql = ocsf_sql(
        r#"class_uid=1005 | where module.file.signatures.state="Valid""#,
        "nanosiem",
    );
    assert!(
        sql.contains(r#"event."module"."file"."signatures"[]."state""#),
        "an unpromoted OCSF attribute in a where stage must read the event JSON; SQL:\n{sql}"
    );
    let sql = ocsf_sql(
        r#"class_uid=1007 | where observables.value="Needle.Example""#,
        "nanosiem",
    );
    assert!(
        sql.contains("has(arrayMap(x -> lower(x), ") && sql.contains("'needle.example')"),
        "a promoted array in a where stage keeps membership semantics; SQL:\n{sql}"
    );
    let sql = ocsf_sql(
        r#"class_uid=1007 | where actual_permissions IN (2035711, 5136)"#,
        "nanosiem",
    );
    assert!(
        sql.contains(r#"accurateCastOrNull(event."actual_permissions", 'Float64')"#),
        "a numeric OCSF attribute IN-list in a where stage must read the event JSON numerically; SQL:\n{sql}"
    );
    // After a projection the stage carries only the projected names (no
    // `event`), so the where keeps the bare projected reference.
    let sql = ocsf_sql(
        r#"class_uid=1007 | table timestamp, actor.process.file.name | where actor.process.file.name="x""#,
        "nanosiem",
    );
    let where_stage = sql.rsplit("stage_2 AS (").next().unwrap_or("");
    assert!(
        where_stage.contains(r#""actor.process.file.name""#) && !where_stage.contains("event."),
        "after `table` the where must use the projected alias; SQL:\n{sql}"
    );
    // `observables.type_id=*` is an existence test on the array, not match-all.
    let sql = ocsf_sql("observables.type_id=*", "nanosiem");
    assert!(sql.contains(r#"notEmpty("observables.type_id")"#), "{sql}");
    // A pipeline-computed name shadows the schema and stays a bare reference.
    let sql = ocsf_sql(
        r#"class_uid=1007 | stats count by metadata.log_source | where count > 1"#,
        "nanosiem",
    );
    assert!(sql.contains("count > 1") || sql.contains("`count` > 1") || sql.contains("\"count\" > 1"), "{sql}");
}

/// NAN-4903 (pure SQL-gen): OCSF 1.9 defines `risk_score` / `risk_level` on 87
/// classes, but the bare names are owned by risk-based alerting and keep
/// reading the `unmapped` spill the finding writer populates; the producer's
/// native value is reachable explicitly as `event.risk_score`.
#[test]
fn rba_names_read_unmapped_and_event_prefix_reads_native_ocsf() {
    let sql = ocsf_sql(r#"risk_level="high""#, "nanosiem");
    assert!(sql.contains(r#"unmapped."risk_level""#), "{sql}");
    // Same for a UDM-era alias that collides with an OCSF attribute name.
    let sql = ocsf_sql(r#"event.auth_type="publickey""#, "nanosiem");
    assert!(sql.contains(r#"event."auth_type""#) && !sql.contains("auth_protocol_id"), "{sql}");
    let sql = ocsf_sql(r#"event.risk_level="high""#, "nanosiem");
    assert!(
        sql.contains(r#"event."risk_level""#) && !sql.contains(r#"unmapped."risk_level""#),
        "{sql}"
    );
}

/// Queries of the codex review fixes (NAN-4903), shared by the SQL-shape test
/// and the live-execution test below.
const REVIEW_QUERIES: &[&str] = &[
    r#"observables.value IN ("Needle.Example", "b")"#,
    r#"observables.type_id IN (1, 2)"#,
    r#"observables.value NOT IN ("x")"#,
    r#"class_uid=1007 | where observables.value IN ("Needle.Example")"#,
    r#"class_uid=1007 | where observables.type_id IN (1, 2)"#,
    r#"class_uid=1005 | table timestamp, module.file.signatures.state | where module.file.signatures.state="valid""#,
    r#"class_uid=1005 | table timestamp, module.file.signatures.state | where module.file.signatures.state IN ("valid")"#,
    r#"class_uid=1007 | where actual_permissions > 0"#,
    r#"class_uid=1007 | fields - message | where metadata.log_source="windows_sysmon""#,
    r#"class_uid=1007 | rename process.name as pname | where metadata.log_source="windows_sysmon""#,
    r#"class_uid=1007 | join type=left device.hostname [search class_uid=3002 | fields device.hostname, src_endpoint.ip] | where metadata.log_source="windows_sysmon""#,
];

/// NAN-4903 codex P1s (pure SQL-gen): array IN/NOT IN is element membership,
/// projected JSON arrays keep membership after `| table`, numeric JSON
/// attributes compare numerically in `| where`, and wildcard-preserving stages
/// (`fields -`, `rename`, `join`) keep alias resolution alive.
#[test]
fn review_fixes_array_in_numeric_where_and_wide_stages() {
    let sql = ocsf_sql(REVIEW_QUERIES[0], "nanosiem");
    assert!(
        sql.contains(r#"arrayExists(x -> x IN ('needle.example', 'b'), arrayMap(x -> lower(x), "observables.value"))"#),
        "{sql}"
    );
    let sql = ocsf_sql(REVIEW_QUERIES[1], "nanosiem");
    assert!(sql.contains(r#"arrayExists(x -> x IN (1, 2), "observables.type_id")"#), "{sql}");
    let sql = ocsf_sql(REVIEW_QUERIES[2], "nanosiem");
    assert!(sql.contains(r#"NOT arrayExists(x -> x IN ('x'), arrayMap(x -> lower(x), "observables.value"))"#), "{sql}");
    let sql = ocsf_sql(REVIEW_QUERIES[3], "nanosiem");
    assert!(sql.contains(r#"arrayExists(x -> x IN ('needle.example'), arrayMap(x -> lower(x), "observables.value"))"#), "{sql}");
    let sql = ocsf_sql(REVIEW_QUERIES[4], "nanosiem");
    assert!(sql.contains(r#"arrayExists(x -> x IN (1, 2), "observables.type_id")"#), "{sql}");

    for q in [REVIEW_QUERIES[5], REVIEW_QUERIES[6]] {
        let sql = ocsf_sql(q, "nanosiem");
        let last = sql.rsplit("stage_2 AS (").next().unwrap_or("");
        assert!(
            last.contains(r#"arrayMap(x -> lower(x), "module.file.signatures.state")"#)
                && !last.contains("event."),
            "after `table` the projected array keeps membership semantics; SQL:\n{sql}"
        );
    }

    let sql = ocsf_sql(REVIEW_QUERIES[7], "nanosiem");
    assert!(
        sql.contains(r#"accurateCastOrNull(event."actual_permissions", 'Float64')"#),
        "numeric attribute must use the numeric extractor; SQL:\n{sql}"
    );

    for q in &REVIEW_QUERIES[8..] {
        let sql = ocsf_sql(q, "nanosiem");
        let last = sql.rsplit("WHERE").next().unwrap_or("");
        assert!(
            !last.contains(r#""metadata.log_source""#) && last.contains("source_type"),
            "`{q}`: wide stage must keep alias resolution; SQL:\n{sql}"
        );
    }
}

/// NAN-4903: the review queries execute without ClickHouse errors against a
/// migrated `nanosiem.ocsf_logs` (skips when none is reachable).
#[tokio::test]
async fn review_fix_queries_execute_against_migrated_store() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        return;
    }
    let client = reqwest::Client::new();
    if !reachable(&client).await {
        eprintln!("Skipping: ClickHouse not reachable");
        return;
    }
    let has_store = exec(
        &client,
        "SELECT count() FROM system.columns WHERE database = 'nanosiem' AND table = 'ocsf_logs' AND name = 'event'",
    )
    .await
    .unwrap_or_default();
    if has_store.trim() != "1" {
        eprintln!("Skipping: nanosiem.ocsf_logs (NAN-4903 shape) not present");
        return;
    }
    let mut errors = Vec::new();
    for q in REVIEW_QUERIES {
        let sql = format!("{} FORMAT Null", ocsf_sql(q, "nanosiem"));
        if let Err(e) = exec(&client, &sql).await {
            errors.push(format!("{q}\n{e}\n{sql}"));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n\n"));
}

/// NAN-4903 codex P2: `metadata.log_source` reads `source_type`, and the
/// predicate is emitted as exactly `lower(source_type) = '…'` — the expression
/// `idx_source_type_lower_set` indexes (skip indexes match by expression), so
/// the 129 upstream rule references prune by source.
///
/// The live half EXPLAINs it against a throwaway database built from the
/// generated DDL (TTL stripped) and seeded with one fixture row: EXPLAIN only
/// lists a skip index when the table has a part to apply it to, so it must not
/// depend on whatever `nanosiem.ocsf_logs` happens to hold (NAN-4903 follow-up).
#[tokio::test]
async fn log_source_predicate_matches_the_lower_source_type_index() {
    let npl = r#"class_uid=1007 metadata.log_source="windows_sysmon" | stats count"#;
    let sql = ocsf_sql(npl, "nanosiem");
    assert!(sql.contains("lower(source_type) = 'windows_sysmon'"), "{sql}");
    assert!(DDL.contains("INDEX idx_source_type_lower_set lower(source_type) TYPE set"), "index must be on lower(source_type)");

    let client = reqwest::Client::new();
    if std::env::var("SKIP_DB_TESTS").is_ok() || !reachable(&client).await {
        return;
    }
    if !enrichment_dicts_present(&client).await {
        eprintln!("Skipping EXPLAIN: the OCSF derivation MV needs the migrated nanosiem enrichment dictionaries");
        return;
    }
    let db = format!("ocsf_explain_{}", uuid::Uuid::now_v7().simple());
    exec(&client, &format!("CREATE DATABASE {db}")).await.expect("create throwaway db");
    let result = explain_log_source_index(&client, &db, npl).await;
    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    result.unwrap();
}

/// The throwaway `ocsf_logs_raw_mv` reads `nanosiem.*` enrichment
/// dictionaries cross-database, so seeding needs a migrated ClickHouse.
async fn enrichment_dicts_present(client: &reqwest::Client) -> bool {
    exec(
        client,
        "SELECT count() FROM system.dictionaries WHERE database = 'nanosiem' \
         AND name IN ('ip_enrichment_dict', 'ioc_enrichment_dict', 'custom_enrichment_dict')",
    )
    .await
    .is_ok_and(|n| n.trim() == "3")
}

async fn explain_log_source_index(client: &reqwest::Client, db: &str, npl: &str) -> Result<(), String> {
    for stmt in test_table_ddl(db) {
        exec(client, &stmt).await?;
    }
    let process = FIXTURES.iter().find(|(name, _)| *name == "process").unwrap().1;
    insert_event(client, db, process).await?;
    let rows = exec(client, &format!("SELECT count() FROM {db}.ocsf_logs")).await?;
    if rows.trim() != "1" {
        return Err(format!("seed row did not land in {db}.ocsf_logs (count = {})", rows.trim()));
    }
    let plan = exec(client, &format!("EXPLAIN indexes = 1 {}", ocsf_sql(npl, db))).await?;
    if plan.contains("idx_source_type_lower_set") {
        Ok(())
    } else {
        Err(format!("index not used:\n{plan}"))
    }
}

/// NAN-4902: `sort` on a name the profile reads from a differently named
/// column (`action` → `activity`) orders by that column while the base scan is
/// in scope (the bare `action` was Code 47), and keeps the projected alias
/// after a stats stage. `stats by <field>_expanded` after `mvexpand` groups by
/// the expanded column, not an `unmapped` JSON path (every key was '').
#[test]
fn sort_alias_and_mvexpand_output_resolve_under_ocsf() {
    let sql = ocsf_sql("* | sort action | head 5", "nanosiem");
    assert!(sql.contains("ORDER BY activity ASC"), "{sql}");
    let sql = ocsf_sql("* | stats count by action | sort -action", "nanosiem");
    assert!(sql.contains("ORDER BY action DESC"), "{sql}");
    // The physical column kept by a projection answers for its alias.
    let sql = ocsf_sql("* | stats count by activity | sort action", "nanosiem");
    assert!(sql.contains("ORDER BY activity ASC"), "{sql}");
    let sql = ocsf_sql("* | table activity | sort -action", "nanosiem");
    assert!(sql.contains("ORDER BY activity DESC"), "{sql}");
    let sql = ocsf_sql("* | mvexpand resources.type | stats count by resources.type_expanded", "nanosiem");
    assert!(sql.contains(r#"GROUP BY "resources.type_expanded""#), "{sql}");
    assert!(!sql.contains("type_expanded\")"), "must not read a JSON path: {sql}");
}

/// NAN-4902: the two queries above execute and answer correctly on a
/// throwaway store seeded with fixture rows plus one multi-resource event.
#[tokio::test]
async fn sort_alias_and_mvexpand_execute_against_seeded_store() {
    let client = reqwest::Client::new();
    if std::env::var("SKIP_DB_TESTS").is_ok() || !reachable(&client).await {
        return;
    }
    if !enrichment_dicts_present(&client).await {
        eprintln!("Skipping: the OCSF derivation MV needs the migrated nanosiem enrichment dictionaries");
        return;
    }
    let db = format!("ocsf_lanei_{}", uuid::Uuid::now_v7().simple());
    exec(&client, &format!("CREATE DATABASE {db}")).await.expect("create throwaway db");
    let result = sort_and_mvexpand_assertions(&client, &db).await;
    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    result.unwrap();
}

async fn sort_and_mvexpand_assertions(client: &reqwest::Client, db: &str) -> Result<(), String> {
    for stmt in test_table_ddl(db) {
        exec(client, &stmt).await?;
    }
    for name in ["process", "auth", "file"] {
        let event = FIXTURES.iter().find(|(n, _)| *n == name).unwrap().1;
        insert_event(client, db, event).await?;
    }
    let api = serde_json::json!({
        "class_uid": 6003, "category_uid": 6, "activity_id": 1, "type_uid": 600301,
        "time": 1749081722345_i64,
        "metadata": {"version": "1.9.0", "log_source": "aws_cloudtrail", "product": {"name": "CloudTrail"}},
        "resources": [{"type": "AWS::S3::Bucket", "uid": "u1"}, {"type": "AWS::IAM::Role", "uid": "u2"}]
    });
    insert_event(client, db, &api.to_string()).await?;

    let rows = exec(client, &format!("{} FORMAT TSV", ocsf_sql("* | sort action | table action", db))).await?;
    let actions: Vec<&str> = rows.lines().collect();
    let mut sorted = actions.clone();
    sorted.sort();
    if actions.len() != 4 || actions != sorted {
        return Err(format!("sort action: {actions:?}"));
    }

    for npl in ["* | stats count by activity | sort action", "* | table activity | sort action"] {
        let rows = exec(client, &format!("{} FORMAT TSV", ocsf_sql(npl, db))).await?;
        let keys: Vec<&str> = rows.lines().map(|l| l.split('\t').next().unwrap_or("")).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        if keys.is_empty() || keys != sorted {
            return Err(format!("{npl}: {keys:?}"));
        }
    }

    let npl = "* | mvexpand resources.type | stats count by resources.type_expanded | sort resources.type_expanded";
    let rows = exec(client, &format!("{} FORMAT TSV", ocsf_sql(npl, db))).await?;
    if rows.trim() != "AWS::IAM::Role\t1\nAWS::S3::Bucket\t1" {
        return Err(format!("mvexpand stats: {rows:?}"));
    }
    Ok(())
}
