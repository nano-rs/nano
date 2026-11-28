// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-5662: the Rarity chart's in-window observation counts OCSF hosts the
//! same way the OCSF prevalence MVs do.
//!
//! The web builds `<path>="a" OR … | <OCSF_HOST_IDENTITY_EVAL> | stats dc(__h)
//! as hosts … by <path>` (nanosiem-web/src/lib/prevalence/inWindowObservation.ts)
//! when the baseline has no count for an artifact. Its old OCSF eval keyed on
//! device.hostname, then src_endpoint.hostname, and never on src_endpoint.ip,
//! so a proxy row (client IP only, device = the appliance) collapsed every
//! client into one host: github.com on 1,108 client IPs counted 1, and plotted
//! RARE.
//!
//! This reads the eval string out of the shipped TypeScript, compiles the exact
//! observation nPL with the OCSF profile, runs it on real ClickHouse over seeded
//! proxy rows, and checks it against (a) the true distinct client IPs and (b)
//! the MV host key (`clickhouse/ocsf/init.sql`) evaluated over the same rows.
//! The old eval is run too, to pin the regression.
//!
//! Requires a ClickHouse with DDL rights (CLICKHOUSE_TEST_URL, default
//! http://localhost:8123; CLICKHOUSE_ADMIN_USER / CLICKHOUSE_ADMIN_PASSWORD).
//! Skips cleanly when unreachable or when `SKIP_DB_TESTS` is set.
//!   cargo test -p nanosiem-core --test rarity_ocsf_host_identity_integration -- --nocapture

use std::sync::Arc;

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::{OcsfProfile, SchemaProfile};

/// Read at run time, not `include_str!`: a compile-time include of a path a
/// mirror may strip breaks the build there.
const WEB_MODULE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../nanosiem-web/src/lib/prevalence/inWindowObservation.ts"
);

/// The pre-NAN-5662 OCSF eval (device first, never the client IP).
const OLD_EVAL: &str = r#"eval __h=if(device.hostname!="", device.hostname, if(src_endpoint.hostname!="", src_endpoint.hostname, "unknown"))"#;

/// The MV host key, verbatim from clickhouse/ocsf/init.sql.
const MV_HOST_KEY: &str = "if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown')))";

fn ch_url() -> String {
    nanosiem_test_db::require_ch_url()
}
fn ch_user() -> String {
    std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or_else(|_| "nanosiem_admin".into())
}
fn ch_pass() -> String {
    std::env::var("CLICKHOUSE_ADMIN_PASSWORD").unwrap_or_else(|_| "nanosiem_admin_secret".into())
}

async fn exec(client: &reqwest::Client, sql: &str) -> Result<String, String> {
    let resp = client
        .post(format!("{}/?enable_full_text_index=1", ch_url()))
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

/// `OCSF_HOST_IDENTITY_EVAL` as the web ships it: the single-quoted pieces of
/// the `export const … = '…' + '…';` initializer, concatenated.
fn shipped_ocsf_eval(web_module: &str) -> String {
    let start = web_module
        .find("export const OCSF_HOST_IDENTITY_EVAL =")
        .expect("OCSF_HOST_IDENTITY_EVAL not found in inWindowObservation.ts");
    let rest = &web_module[start..];
    let init = &rest[rest.find('=').unwrap() + 1..rest.find(';').unwrap()];
    let mut out = String::new();
    let mut in_str = false;
    for ch in init.chars() {
        match (ch, in_str) {
            ('\'', _) => in_str = !in_str,
            (c, true) => out.push(c),
            _ => {}
        }
    }
    assert!(out.starts_with("eval __h="), "unexpected eval: {out}");
    out
}

fn window() -> TimeRange {
    let end = chrono::Utc::now() + chrono::Duration::hours(1);
    TimeRange {
        start: end - chrono::Duration::days(1),
        end,
    }
}

/// The observation nPL, shaped exactly like `buildObservationQuery`.
fn observation_npl(path: &str, artifacts: &[&str], host_eval: &str) -> String {
    let predicate = artifacts
        .iter()
        .map(|a| format!("{path}=\"{a}\""))
        .collect::<Vec<_>>()
        .join(" OR ");
    format!(
        "{predicate} | {host_eval} | stats dc(__h) as hosts, count as events, min(timestamp) as first_in_window by {path}"
    )
}

/// `artifact -> hosts` from a JSONEachRow body.
fn hosts_by(body: &str, path: &str) -> std::collections::BTreeMap<String, u64> {
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap_or_else(|e| panic!("{l}: {e}"));
            let key = v[path].as_str().unwrap_or_else(|| panic!("no {path} in {l}")).to_string();
            let hosts = match &v["hosts"] {
                serde_json::Value::Number(n) => n.as_u64().unwrap(),
                serde_json::Value::String(s) => s.parse().unwrap(),
                other => panic!("hosts: {other}"),
            };
            (key, hosts)
        })
        .collect()
}

#[tokio::test]
async fn ocsf_observation_counts_proxy_clients_like_the_prevalence_mvs() {
    // NAN-5964: no localhost default, and this test writes data, so it
    // also needs the destructive-test opt-in.
    if nanosiem_test_db::ch_url().is_err()
        || !matches!(std::env::var("NANOSIEM_ALLOW_DESTRUCTIVE_TESTS").as_deref(), Ok("1" | "true"))
    {
        eprintln!("Skipping: set CLICKHOUSE_TEST_URL to a throwaway ClickHouse and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1");
        return;
    }
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return;
    }
    let client = reqwest::Client::new();
    if exec(&client, "SELECT 1").await.map(|b| b.trim() == "1") != Ok(true) {
        eprintln!("Skipping: ClickHouse not reachable at {}", ch_url());
        return;
    }
    let Ok(web_module) = std::fs::read_to_string(WEB_MODULE_PATH) else {
        eprintln!("Skipping: {WEB_MODULE_PATH} not present in this checkout");
        return;
    };
    let new_eval = shipped_ocsf_eval(&web_module);

    let db = format!(
        "n5662_rarity_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    exec(&client, &format!("CREATE DATABASE {db}")).await.expect("create db");
    let profile = OcsfProfile::new();
    let own = [
        "device.hostname",
        "src_endpoint.ip",
        "src_endpoint.hostname",
        "dst_endpoint.hostname",
        "http_request.url.hostname",
    ];
    let materialized: String = profile
        .materialized_columns()
        .iter()
        .copied()
        .filter(|c| !own.contains(c) && *c != "src_host_unified")
        .map(|c| format!(", `{c}` String DEFAULT ''"))
        .collect();
    exec(
        &client,
        &format!(
            "CREATE TABLE {db}.ocsf_logs (
                timestamp DateTime64(6, 'UTC'), id UUID, message String,
                source_type LowCardinality(String), class_uid UInt32,
                `device.hostname` String, `src_endpoint.ip` String,
                `src_endpoint.hostname` String, `dst_endpoint.hostname` String,
                `http_request.url.hostname` String,
                `src_host_unified` String ALIAS if(notEmpty(`src_endpoint.hostname`), `src_endpoint.hostname`, `device.hostname`),
                event JSON, unmapped JSON{materialized})
             ENGINE = MergeTree ORDER BY (timestamp, id)"
        ),
    )
    .await
    .expect("create table");

    // Proxy rows (HTTP Activity 4002): client IP, requested host, appliance as
    // device; no src_endpoint.hostname. github.com: 1,108 clients x 3 requests;
    // rare.example.org: 2 clients; api.example.net (URL host only): 50 clients.
    // Plus endpoint rows (no src_endpoint) on 4 workstations for one domain.
    let seed = format!(
        "INSERT INTO {db}.ocsf_logs (timestamp, id, message, source_type, class_uid,
            `device.hostname`, `src_endpoint.ip`, `src_endpoint.hostname`,
            `dst_endpoint.hostname`, `http_request.url.hostname`, event, unmapped)
         SELECT now64(6) - toIntervalSecond(number), generateUUIDv4(), 'proxy', 'squid', 4002,
            'proxy-01', IPv4NumToString(toUInt32(167772160 + intDiv(number, 3))), '',
            'github.com', 'github.com', '{{}}', '{{}}'
         FROM numbers(3324)
         UNION ALL
         SELECT now64(6) - toIntervalSecond(number), generateUUIDv4(), 'proxy', 'squid', 4002,
            'proxy-01', IPv4NumToString(toUInt32(167837696 + (number % 2))), '',
            'rare.example.org', '', '{{}}', '{{}}'
         FROM numbers(10)
         UNION ALL
         SELECT now64(6) - toIntervalSecond(number), generateUUIDv4(), 'proxy', 'squid', 4002,
            'proxy-01', IPv4NumToString(toUInt32(167903232 + number)), '',
            '', 'api.example.net', '{{}}', '{{}}'
         FROM numbers(50)
         UNION ALL
         SELECT now64(6) - toIntervalSecond(number), generateUUIDv4(), 'dns', 'sysmon', 4003,
            concat('ws-', toString(number % 4)), '', '',
            'endpoint.example.com', '', '{{}}', '{{}}'
         FROM numbers(40)"
    );
    exec(&client, &seed).await.expect("seed");

    let table = format!("{db}.ocsf_logs");
    let run = |npl: String| {
        let client = client.clone();
        let table = table.clone();
        async move {
            let query = parse_query(&npl).unwrap_or_else(|e| panic!("{npl}: {e}"));
            let sql = ClickHouseSqlGenerator::with_table(table)
                .with_profile(Arc::new(OcsfProfile::new()))
                .generate(&query, &window())
                .unwrap_or_else(|e| panic!("{npl}: {e}"));
            let body = exec(&client, &format!("{sql} FORMAT JSONEachRow"))
                .await
                .unwrap_or_else(|e| panic!("{npl}\n{sql}\n{e}"));
            (npl, body)
        }
    };

    let domains = ["github.com", "rare.example.org", "endpoint.example.com"];
    let truth = [("github.com", 1108u64), ("rare.example.org", 2), ("endpoint.example.com", 4)];

    // The MV host key over the same rows: what the baseline would count.
    let mv_sql = format!(
        "SELECT `dst_endpoint.hostname` AS d, uniqExact({MV_HOST_KEY}) AS hosts
         FROM {table} WHERE d IN ('github.com', 'rare.example.org', 'endpoint.example.com')
         GROUP BY d ORDER BY d FORMAT JSONEachRow"
    );
    let mv_body = exec(&client, &mv_sql).await.expect("mv key query");
    let mv: std::collections::BTreeMap<String, u64> = mv_body
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            (v["d"].as_str().unwrap().to_string(), v["hosts"].as_str().map_or_else(|| v["hosts"].as_u64().unwrap(), |s| s.parse().unwrap()))
        })
        .collect();

    let (npl, body) = run(observation_npl("dst_endpoint.hostname", &domains, &new_eval)).await;
    let got = hosts_by(&body, "dst_endpoint.hostname");
    eprintln!("NEW  {npl}\n  -> {got:?}\n  MV key -> {mv:?}");
    for (d, n) in truth {
        assert_eq!(got.get(d), Some(&n), "new eval, {d}: {body}");
        assert_eq!(mv.get(d), Some(&n), "MV key, {d}: {mv_body}");
    }

    let (npl, body) = run(observation_npl("http_request.url.hostname", &["api.example.net", "github.com"], &new_eval)).await;
    let got = hosts_by(&body, "http_request.url.hostname");
    eprintln!("NEW  {npl}\n  -> {got:?}");
    assert_eq!(got.get("api.example.net"), Some(&50));
    assert_eq!(got.get("github.com"), Some(&1108));

    // The regression: the old eval counts every proxy client as the appliance.
    let (npl, body) = run(observation_npl("dst_endpoint.hostname", &domains, OLD_EVAL)).await;
    let old = hosts_by(&body, "dst_endpoint.hostname");
    eprintln!("OLD  {npl}\n  -> {old:?}");
    assert_eq!(old.get("github.com"), Some(&1));
    assert_eq!(old.get("rare.example.org"), Some(&1));

    exec(&client, &format!("DROP DATABASE {db}")).await.expect("drop db");
}
