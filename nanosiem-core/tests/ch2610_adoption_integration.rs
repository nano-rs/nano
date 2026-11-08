// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! ClickHouse 26.10 feature adoption (CH-2610 bench) — real-ClickHouse gates.
//!
//! 1. **Lowered `LIKE` instead of `iLike`.** On 26.10.3.7 the `lower(col)` text
//!    index no longer serves `lower(col) iLike '%kw%'` (26.5.7 did), while
//!    `lower(col) LIKE '%kw%'` is still evaluated by the index dictionary scan.
//!    NAN-4943: every literal case-insensitive pattern now emits
//!    `lower(col) LIKE` (no s/k exception). This test runs the generated SQL
//!    and the same SQL with every `LIKE` put back to `iLike` against one table
//!    and requires identical counts on ASCII data (the U+212A / U+017F
//!    differences are pinned in `ci_like_parity_integration`), and checks the
//!    text index PRUNES granules in `EXPLAIN indexes=1` — k-patterns included.
//! 2. **JSON type hints on `event`.** `json_hints.json` paths are typed
//!    `Nullable(String)` / `LowCardinality(Nullable(String))` paths. The
//!    generated OCSF SQL is the same with or without a hint, so it must return
//!    the same rows on a hinted and an unhinted table (equality, presence,
//!    `stats by`, full-row JSON with `type_json_skip_null_typed_paths = 1`).
//!
//! Requires a ClickHouse with DDL rights (CLICKHOUSE_TEST_URL, default
//! http://localhost:8123; CLICKHOUSE_ADMIN_USER / CLICKHOUSE_ADMIN_PASSWORD).
//! Skips cleanly when unreachable or when `SKIP_DB_TESTS` is set.
//!   cargo test -p nanosiem-core --test ch2610_adoption_integration -- --nocapture

use std::sync::Arc;

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::OcsfProfile;

const JSON_HINTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/ocsf/events/json_hints.json"
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

/// JSONEachRow insert: statement in the URL, rows in the body (reqwest drops
/// the data part of an inline statement+data body).
async fn insert(client: &reqwest::Client, table: &str, rows: &str) {
    let stmt = format!("INSERT INTO {table} FORMAT JSONEachRow").replace(' ', "%20");
    let url = format!(
        "{}/?query={stmt}&async_insert=0&wait_end_of_query=1&date_time_input_format=best_effort",
        ch_url()
    );
    let resp = client
        .post(url)
        .basic_auth(ch_user(), Some(ch_pass()))
        .body(rows.to_string())
        .send()
        .await
        .expect("insert request");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "insert into {table} failed: {body}");
}

async fn setup(prefix: &str) -> Option<(reqwest::Client, String)> {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return None;
    }
    let client = reqwest::Client::new();
    if exec(&client, "SELECT 1").await.map(|b| b.trim() == "1") != Ok(true) {
        eprintln!("Skipping: ClickHouse not reachable at {}", ch_url());
        return None;
    }
    let db = format!(
        "{prefix}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    exec(&client, &format!("CREATE DATABASE {db}")).await.expect("create db");
    Some((client, db))
}

fn window() -> TimeRange {
    let end = chrono::Utc::now() + chrono::Duration::hours(1);
    TimeRange {
        start: end - chrono::Duration::days(2),
        end,
    }
}

/// Undo the CH-2610 operator change: the pre-change SQL used `iLike` everywhere.
fn as_ilike(sql: &str) -> String {
    sql.replace(" NOT LIKE '", " NOT iLike '").replace(" LIKE '", " iLike '")
}

/// `(selected, total)` granules after the named skip index in an
/// `EXPLAIN indexes = 1` plan.
fn text_index_granules(explain: &str, idx: &str) -> Option<(u64, u64)> {
    let after = &explain[explain.find(&format!("Name: {idx}"))?..];
    let line = after.lines().find(|l| l.trim_start().starts_with("Granules:"))?;
    let (a, b) = line.trim().trim_start_matches("Granules:").trim().split_once('/')?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

fn count_of(body: &str) -> u64 {
    body.trim().lines().next().unwrap_or("0").trim().parse().unwrap_or(0)
}

#[tokio::test]
async fn lowered_like_matches_ilike_and_uses_the_text_index() {
    let Some((client, db)) = setup("ch2610_like").await else { return };
    let table = format!("{db}.logs");
    exec(
        &client,
        &format!(
            "CREATE TABLE {table} (
                timestamp DateTime64(3, 'UTC'), id UUID DEFAULT generateUUIDv4(),
                message String, source_type LowCardinality(String), command_line String,
                INDEX idx_message_words lower(message) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 100000000,
                INDEX idx_command_line_words lower(command_line) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 100000000
            ) ENGINE = MergeTree ORDER BY (timestamp, id) SETTINGS index_granularity = 512"
        ),
    )
    .await
    .expect("create logs");

    // 40k filler rows; the needles sit in a few granules, in mixed case, next
    // to LIKE metacharacters, backslashes and non-ASCII text.
    let now = chrono::Utc::now();
    let needles: [(&str, &str); 7] = [
        ("Run NeedleKw7 now", r"C:\Windows\System32\NEEDLEKW7.exe /c"),
        ("AdminExec started by svc", "adminexec --kw7 run"),
        ("Failed Login for bob", "cmd.exe /c echo failed login"),
        ("ÄBC cafe deal 50%_off", "äbc ſtrange 50%_off"),
        ("needlekw7 lower case", r"\\NETLOGON\scripts\needlekw7.bat"),
        ("Mimikatz sekurlsa", "Invoke-Kerberoast -OutputFormat Hashcat"),
        ("MIMIKATZ kerberos::list", "KERBEROS ticket dump"),
    ];
    let mut rows = String::new();
    for i in 0..40_000u32 {
        let ts = (now - chrono::Duration::seconds(i64::from(i))).to_rfc3339();
        let (msg, cmd) = if i % 5_000 == 17 {
            let n = needles[(i / 5_000) as usize % needles.len()];
            // (7 needles over 8 slots: every needle lands at least once)
            (n.0.to_string(), n.1.to_string())
        } else {
            (
                format!("process {} wrote file {:x}", i % 997, i),
                format!("svchost.exe -k netsvcs -p {}", i % 31),
            )
        };
        rows.push_str(
            &serde_json::json!({"timestamp": ts, "message": msg, "source_type": "t", "command_line": cmd})
                .to_string(),
        );
        rows.push('\n');
    }
    insert(&client, &table, &rows).await;
    exec(&client, &format!("OPTIMIZE TABLE {table} FINAL")).await.expect("optimize");

    let gen = ClickHouseSqlGenerator::with_table(table.clone());
    let cases: &[(&str, bool)] = &[
        // (nPL, expect at least one row)
        (r#"message CONTAINS "needlekw7" | stats count"#, true),
        (r#"command_line="*needlekw7*" | stats count"#, true),
        (r#"command_line=/needlekw7/ | stats count"#, true),
        (r#"command_line=/NeedleKw7/ | stats count"#, true),
        (r#"message=/^adminexec.*/ | stats count"#, true),
        (r#"command_line ENDSWITH "kw7 run" | stats count"#, true),
        (r#"command_line STARTSWITH "adminexec" | stats count"#, true),
        (r#"message CONTAINS "failed login" | stats count"#, true),
        (r#"message NOT CONTAINS "needlekw7" | stats count"#, true),
        (r#"message CONTAINS "50%_off" | stats count"#, true),
        (r#"command_line CONTAINS "\\netlogon\\" | stats count"#, true),
        (r#"message CONTAINS "Äbc" | stats count"#, true),
        (r#"message CONTAINS "ell" | stats count"#, false),
        (r#"message STARTSWITH "sv" | stats count"#, false),
        (r#"message NOT STARTSWITH "sv" | stats count"#, true),
        (r#"message="mimi*" | stats count"#, true),
        (r#"message!="mimi*" | stats count"#, true),
        (r#"message CONTAINS "MimiKatz" | stats count"#, true),
        (r#"message NOT CONTAINS "mimikatz" | stats count"#, true),
        (r#"command_line CONTAINS "kerberoast" | stats count"#, true),
        (r#"command_line=/kerberos/ | stats count"#, true),
        (r#"command_line ENDSWITH "hashcat" | stats count"#, true),
        (r#"message LIKE "%KERBEROS%" | stats count"#, true),
        (r#"command_line LIKE "%needlekw7%" | stats count"#, true),
        (r#"*vchost* | stats count"#, false),
        (r#"*Sekurlsa* | stats count"#, true),
    ];
    let mut bad = Vec::new();
    for (npl, want_rows) in cases {
        let sql = gen.generate(&parse_query(npl).unwrap(), &window()).unwrap();
        let old = as_ilike(&sql);
        let new_n = count_of(&exec(&client, &format!("{sql} FORMAT TSV")).await.unwrap());
        let old_n = count_of(&exec(&client, &format!("{old} FORMAT TSV")).await.unwrap());
        if new_n != old_n || (*want_rows && new_n == 0) {
            bad.push(format!("{npl}: LIKE form {new_n} rows, iLike form {old_n}\n  {sql}"));
        }
    }

    // The operator change is only worth it if the index serves the LIKE form —
    // k-patterns included (NAN-4943): the text index must appear AND prune.
    for (npl, idx, want) in [
        (r#"command_line="*adminexec*" | stats count"#, "idx_command_line_words", "lower(command_line) LIKE '%adminexec%'"),
        (r#"command_line="*needlekw7*" | stats count"#, "idx_command_line_words", "lower(command_line) LIKE '%needlekw7%'"),
        (r#"command_line CONTAINS "Kerberoast" | stats count"#, "idx_command_line_words", "lower(command_line) LIKE '%kerberoast%'"),
        (r#"message CONTAINS "mimikatz" | stats count"#, "idx_message_words", "lower(message) LIKE '%mimikatz%'"),
        (r#"message="*kelvin*" | stats count"#, "idx_message_words", "lower(message) LIKE '%kelvin%'"),
    ] {
        let sql = gen.generate(&parse_query(npl).unwrap(), &window()).unwrap();
        assert!(sql.contains(want) && !sql.contains("iLike"), "{sql}");
        let explain = exec(&client, &format!("EXPLAIN indexes = 1 {sql}")).await.unwrap();
        match text_index_granules(&explain, idx) {
            Some((read, total)) if read < total => {}
            other => bad.push(format!("{npl}: {idx} did not prune ({other:?}):\n{explain}")),
        }
    }
    // Non-ASCII: lowered with ClickHouse lower() semantics (ASCII only).
    let sql = gen
        .generate(&parse_query(r#"message CONTAINS "Äbc" | stats count"#).unwrap(), &window())
        .unwrap();
    assert!(sql.contains("lower(message) LIKE '%Äbc%'"), "{sql}");

    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[tokio::test]
async fn json_type_hints_do_not_change_results() {
    let Some((client, db)) = setup("ch2610_hints").await else { return };
    let hints: Vec<serde_json::Value> = serde_json::from_str(JSON_HINTS).unwrap();
    let typed: String = hints
        .iter()
        .map(|h| format!("`{}` {}, ", h["ocsf_path"].as_str().unwrap(), h["ch_type"].as_str().unwrap()))
        .collect();
    for (name, json_type) in [
        ("plain", "JSON(max_dynamic_paths = 1024, SKIP unmapped)".to_string()),
        ("hinted", format!("JSON(max_dynamic_paths = 1024, {typed}SKIP unmapped)")),
    ] {
        exec(
            &client,
            &format!(
                "CREATE TABLE {db}.{name} (timestamp DateTime64(3, 'UTC'), id UUID, message String,
                    source_type LowCardinality(String), event {json_type})
                 ENGINE = MergeTree ORDER BY (timestamp, id)
                 SETTINGS min_bytes_for_wide_part = 0, merge_max_dynamic_subcolumns_in_wide_part = 64"
            ),
        )
        .await
        .expect("create table");
    }

    // Every hinted path: present (mixed case), absent, and explicit null.
    let now = chrono::Utc::now();
    let mut rows = String::new();
    for i in 0..3_000u32 {
        let mut event = serde_json::json!({"class_uid": 4001, "time": 0});
        for (k, h) in hints.iter().enumerate() {
            let path = h["ocsf_path"].as_str().unwrap();
            let v = match (i as usize + k) % 5 {
                0 => serde_json::Value::String(format!("Val{}_{}", i % 7, k)),
                1 => serde_json::Value::String(format!("val{}_{}", i % 3, k)),
                2 => serde_json::Value::Null,
                // An object where OCSF says string (a producer violation). On the
                // plain table it lives in `event.^path`; the hinted table stores
                // its JSON text. Both must answer the same (codex P2). Only in
                // the last 100 rows, so the full-row JSON check below can skip them
                // (object vs JSON-text is the documented representation change).
                3 if i >= 2_900 => serde_json::json!({"nested": format!("Svc_obj{}", i % 2)}),
                _ => continue, // absent
            };
            let mut cur = &mut event;
            let segs: Vec<&str> = path.split('.').collect();
            for s in &segs[..segs.len() - 1] {
                cur = cur
                    .as_object_mut()
                    .unwrap()
                    .entry(s.to_string())
                    .or_insert_with(|| serde_json::json!({}));
            }
            cur.as_object_mut().unwrap().insert(segs[segs.len() - 1].to_string(), v);
        }
        let row = serde_json::json!({
            "timestamp": (now - chrono::Duration::seconds(i64::from(i))).to_rfc3339(),
            "id": format!("00000000-0000-0000-0000-{:012}", i),
            "message": "m", "source_type": "t", "event": event,
        });
        rows.push_str(&row.to_string());
        rows.push('\n');
    }
    for name in ["plain", "hinted"] {
        insert(&client, &format!("{db}.{name}"), &rows).await;
    }

    let gen = |table: &str| {
        ClickHouseSqlGenerator::with_table(table.to_string()).with_profile(Arc::new(OcsfProfile::new()))
    };
    // Boot detection reads `system.columns.type`: all manifest hints on the
    // hinted table, none on the plain one.
    for (name, want) in [("plain", 0), ("hinted", hints.len())] {
        let ty = exec(
            &client,
            &format!(
                "SELECT type FROM system.columns WHERE database = '{db}' AND table = '{name}' AND name = 'event' FORMAT TSVRaw"
            ),
        )
        .await
        .unwrap();
        let live = nanosiem_core::schema::event_json_hints_in_type(ty.trim());
        assert_eq!(live.len(), want, "{name}: detected {live:?} from {ty}");
    }
    // The plain table is generated with no live hints (what boot detection finds
    // on a pre-hint table), the hinted one with all of them live.
    let all_hints = nanosiem_core::schema::manifest_event_json_hints();
    let mut typed_form_seen = false;
    let settings = ", type_json_skip_null_typed_paths = 1";
    let mut bad = Vec::new();
    for h in &hints {
        // `event.` forces the OCSF attribute: a bare UDM-era name (`action`)
        // still resolves to its UDM alias column during the soft-alias window.
        let p = format!("event.{}", h["ocsf_path"].as_str().unwrap());
        for npl in [
            format!(r#"{p}="val1_0" | stats count"#),
            format!(r#"{p}=* | stats count"#),
            format!(r#"{p}!=* | stats count"#),
            format!(r#"{p}="*al*" | stats count"#),
            format!(r#"{p} CONTAINS "svc_obj1" | stats count"#),
            format!("* | stats count by {p} | sort -count, {p}"),
        ] {
            let mut out = Vec::new();
            for name in ["plain", "hinted"] {
                let table = format!("{db}.{name}");
                let query = parse_query(&npl).unwrap();
                let sql = if name == "hinted" {
                    nanosiem_core::schema::with_event_json_hints(&all_hints, || {
                        gen(&table).generate(&query, &window()).unwrap()
                    })
                } else {
                    gen(&table).generate(&query, &window()).unwrap()
                };
                if name == "hinted" && sql.contains("ifNull(toString(event.") {
                    typed_form_seen = true;
                }
                if name == "plain" && sql.contains("ifNull(toString(event.") {
                    bad.push(format!("{npl}: typed fast path used on the unhinted table"));
                }
                out.push(
                    exec(&client, &format!("{sql}{settings} FORMAT TSV"))
                        .await
                        .unwrap_or_else(|e| panic!("{npl}: {e}\n{sql}")),
                );
            }
            if out[0] != out[1] {
                bad.push(format!("{npl}: plain={:?} hinted={:?}", out[0], out[1]));
            }
        }
    }
    assert!(typed_form_seen, "the hinted table never exercised the typed fast path");
    // Full-row event JSON: absent and null hinted paths stay absent.
    let full = "SELECT toJSONString(event) FROM {T} WHERE id < toUUID('00000000-0000-0000-0000-000000002900') ORDER BY id SETTINGS type_json_skip_null_typed_paths = 1 FORMAT TSV";
    let plain = exec(&client, &full.replace("{T}", &format!("{db}.plain"))).await.unwrap();
    let hinted = exec(&client, &full.replace("{T}", &format!("{db}.hinted"))).await.unwrap();
    if plain != hinted {
        bad.push("full-row event JSON differs between the plain and hinted tables".into());
    }

    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
