// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! OCSF Phase 0 (NAN-1242) — materialization integration test.
//!
//! Proves that the ~52 derived `JSONExtract` expressions in
//! `clickhouse/ocsf/init.sql` actually produce the correct promoted-column
//! values from a plain OCSF write (client inserts ONLY the `event` column).
//! Most are `MATERIALIZED`; the sort-key columns `class_uid` / `src_endpoint.ip`
//! (and `timestamp`) are `DEFAULT`-derived from the same `event` (NAN-1334) — a
//! DEFAULT derives identically on an event-only insert, so this test covers both
//! kinds unchanged. This is the gate against the silent-failure class these
//! expressions invite: a wrong JSON path or a broken `arrayFilter` returns
//! NULL/empty, never an error.
//!
//! The test is self-validating: for each fixture it derives the expected value
//! in Rust (lowercasing, SHA-256 array selection, ms timestamp) and compares it
//! to what ClickHouse materialized — a differential check between the DDL and an
//! independent interpretation of the same OCSF record.
//!
//! Requires a local ClickHouse with DDL rights. Skips cleanly if unreachable or
//! if `SKIP_DB_TESTS` is set.
//!   Run: cargo test -p nanosiem-core --test ocsf_materialization_integration -- --nocapture
//!   (local dev CH: docker-compose up -d clickhouse)

use serde_json::Value;

const DDL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));

const FIX_AUTH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/fixtures/authentication_3002_logon.json"
));
const FIX_NETWORK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/fixtures/network_activity_4001_traffic.json"
));
const FIX_PROCESS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/fixtures/process_activity_1007_launch.json"
));
const FIX_FILE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/fixtures/file_activity_1001_delete.json"
));
const FIX_DNS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/fixtures/dns_activity_4003_query.json"
));
const FIX_HTTP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/fixtures/http_activity_4002_get.json"
));

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}
fn ch_user() -> String {
    std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or_else(|_| "nanosiem_admin".into())
}
fn ch_pass() -> String {
    std::env::var("CLICKHOUSE_ADMIN_PASSWORD").unwrap_or_else(|_| "nanosiem_admin_secret".into())
}

/// Execute one statement; returns the response body, or Err with CH's message.
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
    exec(client, "SELECT 1").await.map(|b| b.trim() == "1").unwrap_or(false)
}

/// Insert one JSONEachRow row. The statement goes in the `query` URL param and
/// the JSON data is the body — the canonical CH HTTP insert form. (Putting the
/// statement *and* inline data together in the body works with curl but reqwest
/// silently drops the data portion, landing zero rows.)
async fn insert_row(client: &reqwest::Client, db: &str, row_json: &str) -> Result<(), String> {
    // Statement in the URL `query` param (spaces percent-encoded; CH tolerates
    // bare parens); data is the body. Avoids the inline-statement+data body form
    // whose data reqwest silently drops.
    let stmt = format!("INSERT INTO {db}.ocsf_logs (event) FORMAT JSONEachRow").replace(' ', "%20");
    // Force synchronous inserts: the dev server may default async_insert on, in
    // which case the part flushes after the response returns and a read-back
    // races it (observed count lag 0,0,0,1). wait_end_of_query=1 also blocks
    // until processing completes.
    let url = format!("{}/?query={stmt}&async_insert=0&wait_end_of_query=1", ch_url());
    let resp = client
        .post(url)
        .basic_auth(ch_user(), Some(ch_pass()))
        .body(row_json.to_string())
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

/// A single scalar SELECT against the test table, trimmed.
async fn select1(client: &reqwest::Client, db: &str, expr: &str, where_clause: &str) -> String {
    let sql = format!("SELECT {expr} FROM {db}.ocsf_logs WHERE {where_clause} FORMAT TSV");
    exec(client, &sql).await.expect("select failed").trim().to_string()
}

/// SHA-256 value from an OCSF `fingerprint[]` array (algorithm_id == 3), lowercased.
fn sha256_of(hashes: &Value) -> String {
    hashes
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|h| h["algorithm_id"].as_i64() == Some(3))
                .and_then(|h| h["value"].as_str())
        })
        .map(|s| s.to_lowercase())
        .unwrap_or_default()
}

/// Extract ONLY the `ocsf_logs` CREATE TABLE statement from the canonical DDL,
/// pointed at the test DB. The file is multi-statement (table + prevalence
/// MVs/dictionaries since NAN-1248), and the CH HTTP endpoint rejects
/// multi-statement bodies — this test only needs the table (it validates the
/// materialized columns). Strip `--` comments (so a comment `;` can't truncate
/// the statement early) and the TTL clause (so historical fixtures aren't pruned).
fn test_table_ddl(db: &str) -> String {
    let start = DDL
        .find("CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs")
        .expect("ocsf_logs CREATE TABLE in DDL");
    let from = &DDL[start..];
    let no_comments: String = from
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

#[tokio::test]
async fn ocsf_materialized_columns_populate_from_event_only() {
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

    // Per-run DB name so a leftover from a crashed run can't mask drift.
    let db = format!(
        "ocsf_mat_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    exec(&client, &format!("CREATE DATABASE {db}"))
        .await
        .expect("create test db");

    // Use a closure so we always attempt cleanup, even on assertion panic.
    let result = run_assertions(&client, &db).await;
    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    result.expect("materialization assertions");
}

async fn run_assertions(client: &reqwest::Client, db: &str) -> Result<(), String> {
    exec(client, &test_table_ddl(db)).await?;

    let fixtures = [
        ("auth", FIX_AUTH),
        ("network", FIX_NETWORK),
        ("process", FIX_PROCESS),
        ("file", FIX_FILE),
        ("dns", FIX_DNS),
        ("http", FIX_HTTP),
    ];

    // Insert each fixture into the `event` column ONLY (the client contract).
    for (name, raw) in fixtures {
        let obj: Value = serde_json::from_str(raw).map_err(|e| format!("{name} fixture: {e}"))?;
        let row = serde_json::json!({ "event": obj }).to_string();
        insert_row(client, db, &row).await.map_err(|e| format!("insert {name}: {e}"))?;
    }

    // --- Generic taxonomy parity across ALL four classes ---
    // Proves the JSON type + top-level int extraction work for every event.
    for (name, raw) in fixtures {
        let ev: Value = serde_json::from_str(raw).unwrap();
        let type_uid = ev["type_uid"].as_u64().unwrap();
        let got = select1(
            client,
            db,
            "class_uid, category_uid, activity_id, type_uid, severity_id",
            &format!("type_uid = {type_uid}"),
        )
        .await;
        let cols: Vec<&str> = got.split('\t').collect();
        let want = [
            ev["class_uid"].as_u64().unwrap(),
            ev["category_uid"].as_u64().unwrap(),
            ev["activity_id"].as_u64().unwrap(),
            ev["type_uid"].as_u64().unwrap(),
            ev["severity_id"].as_u64().unwrap(),
        ];
        for (i, w) in want.iter().enumerate() {
            let g: u64 = cols.get(i).and_then(|s| s.parse().ok()).unwrap_or(u64::MAX);
            if g != *w {
                return Err(format!(
                    "{name}: taxonomy column {i} = {g}, expected {w} (row: {got:?})"
                ));
            }
        }
    }

    // --- Deep checks on the file fixture (arrays, dual-user, lowercasing, time) ---
    let file: Value = serde_json::from_str(FIX_FILE).unwrap();
    let where_file = "type_uid = 100104";

    // The headline test: file.hashes[] has BOTH md5 (id=1) and sha256 (id=3).
    // The materialized selector must pick SHA-256 and lowercase it — NOT the md5.
    // NOTE: dotted OCSF column names MUST be backtick-quoted in SELECTs.
    let want_file_sha = sha256_of(&file["file"]["hashes"]);
    let got_file_sha = select1(client, db, "`file.hashes.sha256`", where_file).await;
    if got_file_sha != want_file_sha {
        return Err(format!(
            "`file.hashes.sha256` = {got_file_sha:?}, expected SHA-256 {want_file_sha:?} (selector must skip md5)"
        ));
    }
    let md5 = file["file"]["hashes"][0]["value"].as_str().unwrap().to_lowercase();
    if got_file_sha == md5 {
        return Err("`file.hashes.sha256` picked the MD5 entry — arrayFilter(algorithm_id=3) is wrong".into());
    }

    // Nested array on actor.process.file.hashes[] (deeper path).
    let want_proc_sha = sha256_of(&file["actor"]["process"]["file"]["hashes"]);
    let got_proc_sha = select1(client, db, "`actor.process.file.hashes.sha256`", where_file).await;
    if got_proc_sha != want_proc_sha {
        return Err(format!(
            "`actor.process.file.hashes.sha256` = {got_proc_sha:?}, expected {want_proc_sha:?}"
        ));
    }

    // Dual user paths: file fixture has actor.user.name but NO top-level user.
    let want_actor_user = file["actor"]["user"]["name"].as_str().unwrap().to_lowercase();
    let got_actor_user = select1(client, db, "`actor.user.name`", where_file).await;
    if got_actor_user != want_actor_user {
        return Err(format!(
            "`actor.user.name` = {got_actor_user:?}, expected {want_actor_user:?}"
        ));
    }
    let got_user = select1(client, db, "`user.name`", where_file).await;
    if !got_user.is_empty() {
        return Err(format!(
            "`user.name` = {got_user:?}, expected empty (file event has no top-level user.name)"
        ));
    }

    // timestamp DEFAULT-derives from event.time (epoch ms) — round-trips exactly,
    // guarding the NAN-1123 ms-vs-seconds coercion footgun.
    let want_ms = file["time"].as_u64().unwrap();
    let got_ms = select1(client, db, "toUnixTimestamp64Milli(time_dt)", where_file).await;
    if got_ms.parse::<u64>().ok() != Some(want_ms) {
        return Err(format!(
            "toUnixTimestamp64Milli(time_dt) = {got_ms:?}, expected {want_ms} (ms derivation broken)"
        ));
    }

    // (NAN-1241/1247) The stored `<col>.search` companion columns were removed —
    // full-text is now a text index on the `lower(<col>)` expression, not a
    // column. The base `actor.user.name` is already lowercased at materialization
    // (asserted above), which is what the companion used to duplicate.

    // --- Enrichment: GEO column from src/dst_endpoint.location (dual-mode) ---
    // The network fixture carries dst_endpoint.location.country (ISO code). The
    // promoted dotted column must materialize it verbatim.
    let network: Value = serde_json::from_str(FIX_NETWORK).unwrap();
    let where_net = "type_uid = 400106";
    let want_geo = network["dst_endpoint"]["location"]["country"].as_str().unwrap();
    let got_geo = select1(client, db, "`dst_endpoint.location.country`", where_net).await;
    if got_geo != want_geo {
        return Err(format!(
            "`dst_endpoint.location.country` = {got_geo:?}, expected ISO code {want_geo:?}"
        ));
    }
    // ASN number (numeric, from autonomous_system.number).
    let want_asn = network["dst_endpoint"]["autonomous_system"]["number"].as_u64().unwrap();
    let got_asn = select1(client, db, "`dst_endpoint.autonomous_system.number`", where_net).await;
    if got_asn.parse::<u64>().ok() != Some(want_asn) {
        return Err(format!(
            "`dst_endpoint.autonomous_system.number` = {got_asn:?}, expected {want_asn}"
        ));
    }

    // --- Enrichment: enrichments[] selected BY NAME (ioc + custom) ---
    // The selector arrayFirst(name = '<udm>').value must pick the right entry.
    let want_ioc = enrichment_value(&network["enrichments"], "ioc_dest_ip_threat_type");
    let got_ioc = select1(client, db, "`enrichments.ioc_dest_ip_threat_type`", where_net).await;
    if got_ioc != want_ioc {
        return Err(format!(
            "`enrichments.ioc_dest_ip_threat_type` = {got_ioc:?}, expected {want_ioc:?} (by-name selector wrong)"
        ));
    }
    let want_custom = enrichment_value(&network["enrichments"], "custom_dest_ip_tags");
    let got_custom = select1(client, db, "`enrichments.custom_dest_ip_tags`", where_net).await;
    if got_custom != want_custom {
        return Err(format!(
            "`enrichments.custom_dest_ip_tags` = {got_custom:?}, expected {want_custom:?}"
        ));
    }
    // The other-named entry must NOT bleed into a column it doesn't match.
    let got_wrong = select1(client, db, "`enrichments.ioc_src_ip_threat_type`", where_net).await;
    if !got_wrong.is_empty() {
        return Err(format!(
            "`enrichments.ioc_src_ip_threat_type` = {got_wrong:?}, expected empty (no such-named enrichment on the network event)"
        ));
    }

    // --- DNS (4003) promoted columns: query.hostname + answers[0].rdata ---
    let dns: Value = serde_json::from_str(FIX_DNS).unwrap();
    let where_dns = "type_uid = 400302";
    let want_q = dns["query"]["hostname"].as_str().unwrap();
    let got_q = select1(client, db, "`query.hostname`", where_dns).await;
    if got_q != want_q {
        return Err(format!("`query.hostname` = {got_q:?}, expected {want_q:?}"));
    }
    // answers[] is an array; the column takes the FIRST element's rdata.
    let want_ans = dns["answers"][0]["rdata"].as_str().unwrap();
    let got_ans = select1(client, db, "`answers.rdata`", where_dns).await;
    if got_ans != want_ans {
        return Err(format!(
            "`answers.rdata` = {got_ans:?}, expected first answer rdata {want_ans:?}"
        ));
    }

    // --- HTTP (4002) promoted columns: method, url.path, status code ---
    let http: Value = serde_json::from_str(FIX_HTTP).unwrap();
    let where_http = "type_uid = 400203";
    let want_method = http["http_request"]["http_method"].as_str().unwrap();
    let got_method = select1(client, db, "`http_request.http_method`", where_http).await;
    if got_method != want_method {
        return Err(format!(
            "`http_request.http_method` = {got_method:?}, expected {want_method:?}"
        ));
    }
    let want_path = http["http_request"]["url"]["path"].as_str().unwrap();
    let got_path = select1(client, db, "`http_request.url.path`", where_http).await;
    if got_path != want_path {
        return Err(format!(
            "`http_request.url.path` = {got_path:?}, expected {want_path:?}"
        ));
    }
    let want_code = http["http_response"]["code"].as_u64().unwrap();
    let got_code = select1(client, db, "`http_response.code`", where_http).await;
    if got_code.parse::<u64>().ok() != Some(want_code) {
        return Err(format!(
            "`http_response.code` = {got_code:?}, expected {want_code}"
        ));
    }

    // --- Metadata / provenance promoted columns (NAN-1241) ---
    // The HTTP fixture's `metadata` object carries the full provenance set. Each
    // promoted column must materialize the scalar verbatim (case PRESERVED — these
    // are NOT lower()'d). Headline: metadata.product.name is the OCSF source
    // identifier (the source_type analog the UI's source axis reads).
    let metadata_checks: [(&str, &str); 8] = [
        ("`metadata.product.name`", http["metadata"]["product"]["name"].as_str().unwrap()),
        ("`metadata.product.vendor_name`", http["metadata"]["product"]["vendor_name"].as_str().unwrap()),
        ("`metadata.product.feature.name`", http["metadata"]["product"]["feature"]["name"].as_str().unwrap()),
        ("`metadata.log_name`", http["metadata"]["log_name"].as_str().unwrap()),
        ("`metadata.log_provider`", http["metadata"]["log_provider"].as_str().unwrap()),
        ("`metadata.uid`", http["metadata"]["uid"].as_str().unwrap()),
        ("`metadata.version`", http["metadata"]["version"].as_str().unwrap()),
        ("`metadata.correlation_uid`", http["metadata"]["correlation_uid"].as_str().unwrap()),
    ];
    for (col, want) in metadata_checks {
        let got = select1(client, db, col, where_http).await;
        if got != want {
            return Err(format!(
                "{col} = {got:?}, expected {want:?} (metadata provenance materialization broken)"
            ));
        }
    }
    // Case is preserved (product.name is a display label, not lower()'d like host/ip).
    let got_product = select1(client, db, "`metadata.product.name`", where_http).await;
    if got_product != "Conduit Proxy" {
        return Err(format!(
            "`metadata.product.name` = {got_product:?}, expected case-preserved 'Conduit Proxy' (must NOT be lower()'d)"
        ));
    }

    Ok(())
}

/// The `value` of the enrichments[] entry whose `name` matches, mirroring the
/// DDL's arrayFirst(name = '<udm>').value selector.
fn enrichment_value(enrichments: &Value, name: &str) -> String {
    enrichments
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|e| e["name"].as_str() == Some(name))
                .and_then(|e| e["value"].as_str())
        })
        .unwrap_or_default()
        .to_string()
}
