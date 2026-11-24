// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5793: every converted source-scoped read, run for real against a
//! disposable ClickHouse with denied source names that carry `?`, `'` and
//! `?fields` (see [`super::source_scope_ch_fixture`]).
//!
//! Each read runs twice: as a viewer denied those sources, and unrestricted.
//! The restricted run must succeed and its output must not name a denied
//! source or carry a denied row's marker; the unrestricted run must succeed
//! too (an empty deny list binds nothing). Where the seed makes the denied
//! rows reachable, the unrestricted output must also show them, so the
//! exclusion is real and not an empty read.
//!
//! ```text
//! docker run -d --name nan5793-ch -p 127.0.0.1:18793:8123 \
//!   -e CLICKHOUSE_SKIP_USER_SETUP=1 clickhouse/clickhouse-server:26.10.4.207
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18793 NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 \
//!   cargo test -p nanosiem-core --lib source_scope_bound_ch -- --ignored --nocapture
//! ```

use super::source_scope_ch_fixture::{self as fx, client, leaks, restricted, setup};
use super::*;
use crate::auth::ScopeSet;
use std::collections::BTreeSet;

fn service() -> SearchService {
    let mut svc =
        super::npl_golden_corpus_tests::sql_only_service("ocsf").with_clickhouse_identity(client());
    // Prevalence lookups read the throwaway server too (the test pool's
    // client is unconfigured).
    svc.set_prevalence_service(crate::prevalence::PrevalenceService::new(
        client(),
        crate::db::TableNames::new(false),
    ));
    svc
}

fn range() -> TimeRange {
    let now = chrono::Utc::now();
    TimeRange::new(now - chrono::Duration::hours(2), now + chrono::Duration::minutes(1))
}

fn range_input() -> TimeRangeInput {
    let r = range();
    TimeRangeInput::new(r.start, r.end)
}

/// The asset identity the dossier / events / artifact reads pivot on.
fn identities() -> Vec<serde_json::Value> {
    vec![serde_json::json!({ "ip": fx::SHARED_IP, "hostname": fx::SHARED_HOST })]
}

/// Reads that fail in this throwaway environment for reasons unrelated to
/// source scoping, identically with an EMPTY deny list (whose SQL this change
/// leaves byte-identical): a missing dictionary, or an OCSF column-shape issue
/// in the read itself. For these the test requires only that the restricted
/// run fails the same way, never with a binding error.
const FAILS_UNSCOPED_HERE: &[&str] = &[
    // `dictGetOrDefault('nanosiem.domain_prevalence_dict', …)`: no dictionaries here.
    "asset artifact summary",
    // `Unknown identifier __resource` in the stream sub-query (pre-existing, OCSF).
    "cloud dossier",
    // `resources.type` (Array) compared to '' under OCSF (pre-existing).
    "cloud events (paginated, nPL CTE)",
    "cloud events (fallback CTE)",
    // The artifact extraction (the read under test) runs; the prevalence
    // lookups after it need the `*_prevalence_summary` tables. Before the
    // fix the restricted run failed earlier, on the extraction, with a
    // binding error, which this list does not accept.
    "prevalence scatter artifacts",
    // `| resolve_identity` decorates with `user_registry_dict`. The scoped
    // build side is pinned in `cloud_scope_construction_tests`.
    "cloud user timeline (| resolve_identity)",
];

/// An error caused by the deny-list binding itself: the driver's client-side
/// `?` parse, or ClickHouse's missing-parameter error. (Error texts quote the
/// SQL, which names the parameter, so match the error kinds only.)
fn is_binding_error(e: &str) -> bool {
    e.contains("unbound query argument")
        || e.contains("Substitution")
        || e.contains("UNKNOWN_QUERY_PARAMETER")
}

#[derive(Default)]
struct Report {
    failures: Vec<String>,
    lines: Vec<String>,
}

impl Report {
    /// Record one read. `must_show_denied`: the seed reaches the denied rows
    /// through this read, so the unrestricted output must show them.
    fn check(
        &mut self,
        name: &str,
        restricted: Result<String, String>,
        unrestricted: Result<String, String>,
        must_show_denied: bool,
    ) {
        let r_leaks = restricted.as_ref().map(|o| leaks(o)).unwrap_or_default();
        let u_shows = unrestricted.as_ref().map(|o| !leaks(o).is_empty()).unwrap_or(false);
        self.lines.push(format!(
            "{name:<40} restricted={:<5} leaks={:?} unrestricted={:<5} shows_denied={u_shows}",
            restricted.is_ok(),
            r_leaks,
            unrestricted.is_ok(),
        ));
        let known = FAILS_UNSCOPED_HERE.contains(&name);
        if known {
            match (&restricted, &unrestricted) {
                (Err(r), Err(_)) if !is_binding_error(r) => {}
                _ => self.failures.push(format!(
                    "{name}: listed in FAILS_UNSCOPED_HERE but restricted={:?} unrestricted={:?}; \
                     update the list",
                    restricted.as_ref().map(|_| "ok"),
                    unrestricted.as_ref().map(|_| "ok"),
                )),
            }
            return;
        }
        match &restricted {
            Err(e) => self.failures.push(format!("{name}: restricted read failed: {e}")),
            Ok(o) if !r_leaks.is_empty() => {
                self.failures.push(format!("{name}: restricted read leaked {r_leaks:?}: {o}"))
            }
            Ok(_) => {}
        }
        if let Err(e) = &unrestricted {
            self.failures.push(format!("{name}: unrestricted read failed: {e}"));
        }
        if must_show_denied && unrestricted.is_ok() && !u_shows {
            self.failures.push(format!(
                "{name}: unrestricted output never showed the denied rows, so the \
                 exclusion is not exercised"
            ));
        }
    }

    fn check_eq<T: PartialEq + std::fmt::Debug>(&mut self, name: &str, got: T, want: T) {
        self.lines.push(format!("{name:<40} got={got:?} want={want:?}"));
        if got != want {
            self.failures.push(format!("{name}: got {got:?}, want {want:?}"));
        }
    }

    fn finish(self) {
        for l in &self.lines {
            println!("{l}");
        }
        assert!(self.failures.is_empty(), "failures:\n{}", self.failures.join("\n"));
    }
}

/// JSONEachRow rows a query returns.
async fn json_rows(query: clickhouse::query::Query) -> Result<Vec<serde_json::Value>, String> {
    let mut cursor = query.fetch_bytes("JSONEachRow").map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    while let Some(chunk) = cursor.next().await.map_err(|e| e.to_string())? {
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

async fn count_rows(query: clickhouse::query::Query) -> Result<usize, String> {
    json_rows(query).await.map(|rows| rows.len())
}

fn dbg<T: std::fmt::Debug, E: std::fmt::Display>(r: Result<T, E>) -> Result<String, String> {
    r.map(|v| format!("{v:?}")).map_err(|e| e.to_string())
}

/// The bug and the fix at the driver: the inline literal form fails on a
/// `?` in a denied name; the bound form filters exactly the denied rows.
#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL (a disposable ClickHouse)"]
async fn bound_deny_list_filters_hostile_names_where_the_inline_form_breaks() {
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    setup().await;
    let ch = client();
    let deny = restricted().deny_set().clone();

    let inline = source_scope_literal_predicate("source_type", &deny).unwrap();
    let broken = ch
        .query(&format!("SELECT count() FROM nanosiem.ocsf_logs WHERE {inline}"))
        .fetch_one::<u64>()
        .await;
    assert!(broken.is_err(), "the inline form was expected to break on `?`: {broken:?}");

    let bound = source_scope_bound_predicate("source_type", &deny).unwrap();
    let sql = format!("SELECT source_type FROM nanosiem.ocsf_logs WHERE {bound} ORDER BY source_type");
    let visible = bind_source_scope(ch.query(&sql), &deny)
        .fetch_all::<String>()
        .await
        .expect("bound form executes");
    assert_eq!(visible, vec![fx::ALLOWED.to_string()]);

    // Unrestricted: no predicate, nothing bound, every source visible.
    assert!(source_scope_bound_predicate("source_type", &BTreeSet::new()).is_none());
    let all = bind_source_scope(
        ch.query("SELECT count() FROM nanosiem.ocsf_logs"),
        &BTreeSet::new(),
    )
    .fetch_one::<u64>()
    .await
    .unwrap();
    assert_eq!(all, 1 + fx::DENIED.len() as u64);
}

/// Every converted search-service read (asset, cloud, lateral, retro, otel,
/// field inventory, row fetch).
#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL (a disposable ClickHouse)"]
async fn every_converted_search_read_excludes_denied_sources() {
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    setup().await;
    let svc = service();
    let deny = restricted();
    let open = ScopeSet::unrestricted();
    let tr = range();
    let ids = identities();
    let mut report = Report::default();

    macro_rules! both {
        ($name:expr, $must:expr, |$scope:ident| $call:expr) => {{
            let r = {
                let $scope = &deny;
                dbg($call.await)
            };
            let u = {
                let $scope = &open;
                dbg($call.await)
            };
            report.check($name, r, u, $must);
        }};
    }

    both!("asset dossier", true, |scope| svc.query_asset_dossier(
        "src_ip", fx::SHARED_IP, &ids, &tr, scope
    ));
    both!("asset events (paginated + facets)", true, |scope| svc
        .query_asset_events_paginated("src_ip", fx::SHARED_IP, &ids, &tr, 0, 50, None, scope));
    both!("asset artifact summary", true, |scope| svc.query_asset_artifact_summary(
        "src_ip", fx::SHARED_IP, &ids, &tr, scope
    ));
    both!("asset artifact occurrences", true, |scope| svc
        .query_asset_artifact_occurrences("src_ip", fx::SHARED_IP, &ids, &tr, None, None, scope));
    both!("asset true time range", false, |scope| svc.query_asset_true_time_range(
        "src_ip", fx::SHARED_IP, &ids, scope
    ));
    both!("asset identity resolution", true, |scope| svc.resolve_asset_identities(
        "src_ip",
        fx::SHARED_IP,
        &tr,
        std::time::Duration::from_secs(86_400),
        scope
    ));
    both!("entity dimension firsts", true, |scope| svc.entity_dimension_firsts(
        scope,
        "ip",
        fx::SHARED_IP,
        true,
        &["dest_ip", "dest_host", "process_name"],
        tr.start,
        tr.end,
        10
    ));
    both!("entity hourly activity", false, |scope| svc.entity_hourly_activity_scoped(
        scope,
        "ip",
        fx::SHARED_IP,
        tr.start,
        tr.end
    ));
    both!("cloud dossier", true, |scope| svc.query_cloud_dossier(
        fx::SHARED_USER,
        None,
        None,
        &super::cloud_dossier::CloudDossierFacetFilters::default(),
        &tr,
        scope
    ));
    both!("cloud overview", true, |scope| svc.query_cloud_overview(None, None, &tr, scope));
    both!("cloud events (paginated, nPL CTE)", true, |scope| svc
        .query_cloud_events_paginated("*", &tr, 0, 50, None, scope));
    both!("cloud events (fallback CTE)", true, |scope| svc
        .query_cloud_events_paginated("((( not nPL", &tr, 0, 50, None, scope));
    both!("cloud user timeline", true, |scope| svc.query_cloud_user_timeline(
        "*",
        &tr,
        fx::SHARED_USER,
        scope
    ));
    both!("cloud entity pivot", true, |scope| svc.query_cloud_entity_pivot(
        "*",
        &tr,
        "user",
        fx::SHARED_USER,
        scope
    ));
    let lateral_info = crate::search::query_processing::LateralCommandInfo {
        seed_type: crate::query::LateralSeedType::User,
        entity_field: Some("user".to_string()),
        max_hops: 1,
        time_window: None,
        methods: vec![
            crate::query::LateralMethod::Auth,
            crate::query::LateralMethod::Network,
            crate::query::LateralMethod::Process,
        ],
    };
    let seed = vec![serde_json::json!({ "user": fx::SHARED_USER })];
    both!("lateral hops + hostname resolution", false, |scope| svc
        .build_lateral_view(seed.clone(), &lateral_info, &tr, scope));
    let retro = |q: &str| -> crate::search::RetroRequest {
        serde_json::from_value(serde_json::json!({
            "query": q,
            "time_range": { "start": tr.start, "end": tr.end },
        }))
        .expect("retro request")
    };
    both!("retro summary", false, |scope| svc.build_retro_view(
        retro(&format!("ioc={} | retro", fx::DENIED_DST_IP)),
        scope
    ));
    both!("retro list", false, |scope| svc.build_retro_view(
        retro(&format!("ioc in ({}, {}) | retro", fx::DENIED_DST_IP, fx::ALLOWED_DST_IP)),
        scope
    ));
    both!("retro pivot", false, |scope| svc.build_retro_view(
        retro(&format!("ioc={} | retro by asset", fx::DENIED_DST_IP)),
        scope
    ));
    both!("otel security signals", false, |scope| svc
        .observability_service_security_signals(fx::SPAN_SERVICE, &tr, None, scope));
    let tri = range_input();
    // NAN-5793 review (P2): the scatter's artifact extraction ran the
    // nPL-rendered WHERE (denied names as literals) through `clickhouse.query`,
    // so a `?` in a denied name failed it for every restricted viewer.
    let scatter_request: crate::search::SearchRequest = serde_json::from_value(serde_json::json!({
        "query": "*",
        "time_range": { "start": tr.start, "end": tr.end },
    }))
    .expect("search request");
    both!("prevalence scatter artifacts", true, |scope| svc
        .get_prevalence_artifacts(&scatter_request, scope));
    // NAN-5793 review (P1): `| identity` and a risk subsearch through the
    // cloud CTE, now generated with the caller's deny-set.
    both!("cloud user timeline (| resolve_identity)", false, |scope| svc.query_cloud_user_timeline(
        "* | resolve_identity field=src_ip",
        &tr,
        fx::SHARED_USER,
        scope
    ));
    both!("field inventory (spill)", false, |scope| svc.get_dynamic_field_inventory(
        DynamicFieldBucket::Spill,
        Some("*"),
        Some(&tri),
        scope,
        None
    ));

    // Row fetch by id: the denied row resolves for an unrestricted viewer and
    // not at all for the restricted one.
    let denied_id: String = client()
        .query("SELECT toString(id) FROM nanosiem.ocsf_logs WHERE source_type = ? LIMIT 1")
        .bind(fx::DENIED[0])
        .fetch_one()
        .await
        .unwrap();
    let r = svc.fetch_log_by_id(&denied_id, Some(&tri), None, &deny).await;
    let u = svc.fetch_log_by_id(&denied_id, Some(&tri), None, &open).await;
    report.check_eq("fetch log by id (restricted, denied row)", r.as_ref().map(|o| o.is_some()).ok(), Some(false));
    report.check_eq("fetch log by id (unrestricted, denied row)", u.as_ref().map(|o| o.is_some()).ok(), Some(true));

    report.finish();
}

/// The converted telemetry / health / coverage reads outside search.
#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL (a disposable ClickHouse)"]
async fn every_converted_telemetry_and_health_read_excludes_denied_sources() {
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    setup().await;
    let deny = restricted();
    let open = ScopeSet::unrestricted();
    let tables = crate::db::TableNames::new(false);
    let mut report = Report::default();
    let all_rows = 1 + fx::DENIED.len() as i64;

    // Log telemetry: the rollup (`scope_source_type`) and raw (`source_type`)
    // paths. Every seeded rollup row is 7 events; every raw row is 1.
    let repo = crate::log_telemetry::LogTelemetryRepository::new(client(), tables.clone());
    for (name, scope, want) in [("restricted", &deny, 7), ("unrestricted", &open, 7 * all_rows)] {
        let got = repo.total_events(24, scope.deny_set()).await.map_err(|e| e.to_string());
        report.check_eq(&format!("telemetry total_events rollup ({name})"), got, Ok(want));
        let got = repo
            .buckets_all(24, crate::log_telemetry::BucketSize::Hour, scope.deny_set())
            .await
            .map(|pts| pts.iter().map(|p| p.events as i64).sum::<i64>())
            .map_err(|e| e.to_string());
        report.check_eq(&format!("telemetry buckets_all rollup ({name})"), got, Ok(want));
        let got = repo
            .source_volumes_range(
                crate::schema::SchemaId::Ocsf,
                chrono::Utc::now() - chrono::Duration::hours(2),
                chrono::Utc::now(),
                scope.deny_set(),
                50,
            )
            .await
            .map(|v| v.len())
            .map_err(|e| e.to_string());
        report.check_eq(
            &format!("telemetry source_volumes rollup ({name})"),
            got,
            Ok(if name == "restricted" { 1 } else { all_rows as usize }),
        );
        let sources: Vec<String> = std::iter::once(fx::ALLOWED.to_string())
            .chain(fx::DENIED.iter().map(|d| d.to_lowercase()))
            .collect();
        let got = repo
            .stats_by_source_type(&sources, 24, scope.deny_set())
            .await
            .map(|m| m.contains_key(fx::ALLOWED) && m.keys().all(|k| k == fx::ALLOWED || name == "unrestricted"))
            .map_err(|e| e.to_string());
        report.check_eq(&format!("telemetry stats_by_source_type ({name})"), got, Ok(true));
    }
    // Raw builders (the restricted long-window fallbacks), executed as the
    // repository executes them.
    let raw_start = chrono::Utc::now() - chrono::Duration::hours(2);
    let raw_end = chrono::Utc::now() + chrono::Duration::minutes(1);
    for (name, scope, want) in [("restricted", &deny, 1u64), ("unrestricted", &open, all_rows as u64)] {
        use crate::log_telemetry::repository as lt;
        let d = scope.deny_set();
        let t = "nanosiem.ocsf_logs";
        for (builder, sql) in [
            ("total_events_raw", lt::build_total_events_raw_sql(t, 24, d)),
            ("total_events_range_raw", lt::build_total_events_range_raw_sql(t, raw_start, raw_end, d)),
        ] {
            let got = bind_source_scope(client().query(&sql), d)
                .fetch_one::<u64>()
                .await
                .map_err(|e| e.to_string());
            report.check_eq(&format!("telemetry {builder} ({name})"), got, Ok(want));
        }
        let sql = lt::build_source_volumes_range_raw_sql(t, raw_start, raw_end, d, 50);
        let got = count_rows(bind_source_scope(client().query(&sql), d)).await.map(|n| n as u64);
        report.check_eq(&format!("telemetry source_volumes_raw ({name})"), got, Ok(want));
        let sql = lt::build_buckets_all_raw_sql(t, 24, crate::log_telemetry::BucketSize::Hour, d);
        let got = json_rows(bind_source_scope(client().query(&sql), d)).await.map(|rows| {
            rows.iter()
                .map(|v| {
                    v.get("events")
                        .and_then(|e| e.as_u64().or_else(|| e.as_str()?.parse().ok()))
                        .unwrap_or(0)
                })
                .sum::<u64>()
        });
        report.check_eq(&format!("telemetry buckets_all_raw ({name})"), got, Ok(want));
    }

    // Log-source activity + hourly health series (rollup, raw scope key).
    let reader = crate::log_sources::connect::SourceActivityReader::new(client(), tables.clone());
    let r = dbg(reader.activity(24, &deny).await);
    let u = dbg(reader.activity(24, &open).await);
    report.check("log-source activity", r, u, true);
    // The route keys stay SQL text in this builder (they are log-source keys,
    // not deny names), so only the allowed key is asked for; the deny list
    // binds alongside them.
    for (name, scope) in [("restricted", &deny), ("unrestricted", &open)] {
        let keys = vec![fx::ALLOWED.to_string()];
        let sql = crate::log_sources::health_series::hourly_sql(
            "nanosiem.logs_per_source_5m_v2",
            crate::schema::active_log_telemetry_profile(),
            24,
            scope,
            &keys,
        );
        let got = count_rows(bind_source_scope(client().query(&sql), scope.deny_set())).await;
        report.check_eq(&format!("health series hourly ({name})"), got, Ok(1));
    }

    // SIEM health collectors over the logs table.
    let ch = client();
    let r = dbg::<_, String>(Ok(crate::siem_health::collector::collect_ingestion_metrics(&ch, &ch, false, &deny).await));
    let u = dbg::<_, String>(Ok(crate::siem_health::collector::collect_ingestion_metrics(&ch, &ch, false, &open).await));
    report.check("siem health ingestion", r, u, true);
    let r = dbg::<_, String>(Ok(crate::siem_health::collector::collect_parsing_metrics(&ch, false, &deny).await));
    let u = dbg::<_, String>(Ok(crate::siem_health::collector::collect_parsing_metrics(&ch, false, &open).await));
    report.check("siem health parsing", r, u, false);

    // Marketplace coverage aggregate: the restricted count is the allowed row only.
    let profile = crate::schema::OcsfProfile::new();
    let r = crate::marketplace::coverage::fetch_counts(&ch, &profile, deny.deny_set()).await;
    let u = crate::marketplace::coverage::fetch_counts(&ch, &profile, open.deny_set()).await;
    report.check_eq("marketplace coverage (restricted ran)", r.is_some(), true);
    report.check_eq("marketplace coverage (unrestricted ran)", u.is_some(), true);

    report.finish();
}
