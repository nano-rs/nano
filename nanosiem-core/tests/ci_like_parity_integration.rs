// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-4943 — nPL case-insensitivity is a *lowercase match*, on real ClickHouse.
//!
//! Every case-insensitive pattern compiles to `lower(<col>) [NOT ]LIKE '<lowered>'`
//! (one helper, `ci_like`). This suite runs the generated SQL and requires:
//!
//! 1. **ASCII parity.** For mixed-case ASCII data, `=`, `*kw*`, `kw*`, `*kw`,
//!    `CONTAINS`, `STARTSWITH`, `ENDSWITH`, `LIKE`, a simple regex and the
//!    `| where` forms return exactly the same rows — and the negated forms the
//!    exact complement. Ground truth is ClickHouse `ILIKE` on the raw column.
//! 2. **Pinned non-ASCII outcomes** (documented in `ci_like`):
//!    - U+017F LONG S: `*svchost*` does not match `ſvchost` (26.10 ILIKE did not
//!      either);
//!    - U+212A KELVIN SIGN: `*kelvin*` does not match `Kelvin` written with the
//!      Kelvin sign (26.10 ILIKE did — accepted, NAN-4943);
//!    - `Ä` / `É` / Cyrillic: `lower()` folds ASCII only, so a pattern matches
//!      its own case of a non-ASCII letter only (`*Äbc*` finds `Äbc`, not `äbc`).
//!
//! Requires a ClickHouse with DDL rights (CLICKHOUSE_TEST_URL, default
//! http://localhost:8123; CLICKHOUSE_ADMIN_USER / CLICKHOUSE_ADMIN_PASSWORD).
//! Skips cleanly when unreachable or when `SKIP_DB_TESTS` is set.
//!   cargo test -p nanosiem-core --test ci_like_parity_integration -- --nocapture

use std::collections::BTreeSet;

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};

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

fn window() -> TimeRange {
    let end = chrono::Utc::now() + chrono::Duration::hours(1);
    TimeRange {
        start: end - chrono::Duration::days(2),
        end,
    }
}

/// The `command_line` value of every row, one per line.
const ROWS: &[&str] = &[
    // ASCII needles in every case
    "MimiKatz",
    "mimikatz",
    "MIMIKATZ",
    "mImIkAtZ",
    "Kerberos",
    "KERBEROS",
    "kerberos",
    // LIKE metacharacters and backslashes are literal
    "50%_Off",
    "50x_off",
    r"C:\Windows\NTDS",
    // distractors
    "svchost",
    "powershell",
    // non-ASCII: long s, Kelvin sign, Latin-1, Cyrillic
    "\u{17F}vchost",
    "\u{212A}elvin",
    "kelvin",
    "Äbc",
    "äbc",
    "ÉCOLE",
    "école",
    "Жук",
    "жук",
];

struct Fixture {
    client: reqwest::Client,
    db: String,
    gen: ClickHouseSqlGenerator,
}

async fn fixture() -> Option<Fixture> {
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
        "ci_like_parity_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    exec(&client, &format!("CREATE DATABASE {db}")).await.expect("create db");
    let table = format!("{db}.logs");
    exec(
        &client,
        &format!(
            "CREATE TABLE {table} (
                timestamp DateTime64(3, 'UTC'), id UUID DEFAULT generateUUIDv4(),
                message String, source_type LowCardinality(String), command_line String,
                tags Array(String),
                INDEX idx_command_line_words lower(command_line) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 100000000
            ) ENGINE = MergeTree ORDER BY (timestamp, id)"
        ),
    )
    .await
    .expect("create logs");
    let now = chrono::Utc::now();
    let mut rows = String::new();
    for (i, v) in ROWS.iter().enumerate() {
        let ts = (now - chrono::Duration::seconds(i as i64)).to_rfc3339();
        rows.push_str(
            &serde_json::json!({"timestamp": ts, "message": "m", "source_type": "t", "command_line": v, "tags": [v]})
                .to_string(),
        );
        rows.push('\n');
    }
    insert(&client, &table, &rows).await;
    Some(Fixture { client, db, gen: ClickHouseSqlGenerator::with_table(table) })
}

impl Fixture {
    /// The set of `command_line` values an nPL search returns.
    async fn rows(&self, npl: &str) -> BTreeSet<String> {
        let sql = self
            .gen
            .generate(&parse_query(&format!("{npl} | stats count by command_line")).unwrap(), &window())
            .unwrap_or_else(|e| panic!("{npl}: {e}"));
        assert!(!sql.contains("iLike"), "{npl}: literal pattern still emits iLike:\n{sql}");
        assert!(!sql.contains("PREWHERE"), "{npl}: explicit PREWHERE:\n{sql}");
        let body = exec(&self.client, &format!("{sql} FORMAT TSVRaw"))
            .await
            .unwrap_or_else(|e| panic!("{npl}: {e}\n{sql}"));
        body.lines()
            .filter_map(|l| l.split('\t').find(|c| ROWS.contains(c)).map(str::to_string))
            .collect()
    }

    /// Ground truth: ClickHouse ILIKE on the raw column.
    async fn ilike(&self, pattern: &str) -> BTreeSet<String> {
        let body = exec(
            &self.client,
            &format!(
                "SELECT command_line FROM {}.logs WHERE command_line ILIKE '{}' FORMAT TSVRaw",
                self.db,
                pattern.replace('\\', "\\\\").replace('\'', "''")
            ),
        )
        .await
        .unwrap();
        body.lines().map(str::to_string).collect()
    }

    fn complement(&self, s: &BTreeSet<String>) -> BTreeSet<String> {
        ROWS.iter().map(|r| r.to_string()).filter(|r| !s.contains(r)).collect()
    }
}

fn set(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn ascii_pattern_forms_agree_and_non_ascii_outcomes_are_pinned() {
    let Some(fx) = fixture().await else { return };
    let mut bad = Vec::new();

    // 1. ASCII parity: every form of a whole-value needle, in any case.
    for needle in ["MiMiKaTz", "kerberos", "KERBEROS"] {
        let want = fx.ilike(needle).await;
        assert!(want.len() >= 3, "fixture: {needle} → {want:?}");
        let (head, tail) = needle.split_at(3);
        let positive = [
            format!(r#"command_line="{needle}""#),
            format!(r#"command_line="*{needle}*""#),
            format!(r#"command_line="{head}*""#),
            format!(r#"command_line="*{tail}""#),
            format!(r#"command_line CONTAINS "{needle}""#),
            format!(r#"command_line STARTSWITH "{needle}""#),
            format!(r#"command_line ENDSWITH "{needle}""#),
            format!(r#"command_line LIKE "{needle}""#),
            format!(r#"command_line LIKE "%{needle}%""#),
            format!(r#"command_line=/{needle}/"#),
            format!(r#"command_line=/^{needle}.*/"#),
            format!(r#"* | where command_line CONTAINS "{needle}""#),
            format!(r#"* | where command_line LIKE "{needle}""#),
            format!(r#"* | where command_line STARTSWITH "{head}""#),
            format!(r#"* | where command_line ENDSWITH "{tail}""#),
        ];
        for q in &positive {
            let got = fx.rows(q).await;
            if got != want {
                bad.push(format!("{q}: {got:?} != ILIKE {want:?}"));
            }
        }
        let want_neg = fx.complement(&want);
        for q in [
            format!(r#"command_line!="{needle}""#),
            format!(r#"command_line!="*{needle}*""#),
            format!(r#"command_line NOT CONTAINS "{needle}""#),
            format!(r#"NOT command_line CONTAINS "{needle}""#),
            format!(r#"command_line NOT STARTSWITH "{needle}""#),
            format!(r#"command_line NOT ENDSWITH "{needle}""#),
            format!(r#"command_line NOT LIKE "%{needle}%""#),
            format!(r#"command_line!=/{needle}/"#),
            format!(r#"* | where NOT command_line CONTAINS "{needle}""#),
        ] {
            let got = fx.rows(&q).await;
            if got != want_neg {
                bad.push(format!("{q}: {got:?} != complement {want_neg:?}"));
            }
        }
    }

    // LIKE metacharacters / backslashes in a CONTAINS value are literal;
    // explicit LIKE keeps the user's wildcards.
    for (q, want) in [
        (r#"command_line CONTAINS "50%_off""#, set(&["50%_Off"])),
        (r#"command_line LIKE "50%_off""#, set(&["50%_Off", "50x_off"])),
        (r#"command_line CONTAINS "\\ntds""#, set(&[r"C:\Windows\NTDS"])),
        (r#"command_line="*\\windows\\*""#, set(&[r"C:\Windows\NTDS"])),
    ] {
        let got = fx.rows(q).await;
        if got != want {
            bad.push(format!("{q}: {got:?} != {want:?}"));
        }
    }

    // 2. Pinned non-ASCII outcomes (lowercase match, ClickHouse lower()).
    for (q, want) in [
        // long s: never folded (ILIKE on 26.10 agrees).
        (r#"command_line CONTAINS "svchost""#, set(&["svchost"])),
        (r#"command_line="*SVCHOST*""#, set(&["svchost"])),
        (r#"command_line CONTAINS "ſvchost""#, set(&["\u{17F}vchost"])),
        // Kelvin sign: not folded onto k (26.10 ILIKE did; accepted).
        (r#"command_line CONTAINS "kelvin""#, set(&["kelvin"])),
        (r#"command_line="*KELVIN*""#, set(&["kelvin"])),
        (r#"command_line=/kelvin/"#, set(&["kelvin"])),
        (r#"command_line CONTAINS "Kelvin""#, set(&["\u{212A}elvin"])),
        // Latin-1 / Cyrillic: a non-ASCII letter matches its own case only;
        // the ASCII letters around it still fold.
        (r#"command_line CONTAINS "ÄBC""#, set(&["Äbc"])),
        // `=` / `IN` lower the literal the same way (was Unicode: `="Äbc"`
        // compiled to `= 'äbc'` and missed the stored `Äbc`).
        (r#"command_line="ÄBC""#, set(&["Äbc"])),
        (r#"command_line IN ("ÄBC", "ÉCOLE")"#, set(&["Äbc", "ÉCOLE"])),
        (r#"command_line="жук""#, set(&["жук"])),
        (r#"* | where command_line="ÄBC""#, set(&["Äbc"])),
        (r#"command_line CONTAINS "äbc""#, set(&["äbc"])),
        (r#"command_line="*Écol*""#, set(&["ÉCOLE"])),
        (r#"command_line STARTSWITH "é""#, set(&["école"])),
        (r#"command_line CONTAINS "Жук""#, set(&["Жук"])),
        (r#"command_line ENDSWITH "ук""#, set(&["Жук", "жук"])),
        (r#"command_line LIKE "ж%""#, set(&["жук"])),
    ] {
        let got = fx.rows(q).await;
        if got != want {
            bad.push(format!("{q}: {got:?} != pinned {want:?}"));
        }
    }
    // Non-ASCII simple regex keeps RE2 `match()`, which folds Ä↔ä.
    let got = fx.rows(r#"command_line=/Äbc/"#).await;
    if got != set(&["Äbc", "äbc"]) {
        bad.push(format!("/Äbc/: {got:?}"));
    }

    let _ = exec(&fx.client, &format!("DROP DATABASE IF EXISTS {}", fx.db)).await;
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
