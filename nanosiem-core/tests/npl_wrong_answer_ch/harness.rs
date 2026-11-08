// SPDX-License-Identifier: AGPL-3.0-or-later
//! Disposable-ClickHouse harness for the nPL silent-wrong-answer differential
//! suite (NAN-4902 P0-4). Builds the production `logs` (UDM) and `ocsf_logs`
//! (OCSF) tables from the checked-in DDL in a throwaway database, loads a small
//! fixture through `JSONEachRow`, and runs SQL that the production generator
//! emits through the shared transport (`db::clickhouse_transport`, LZ4 pin).
//!
//! Opt-in: `NANOSIEM_TEST_CLICKHOUSE_URL` (+ optional `_USER` / `_PASSWORD`)
//! must name a disposable ClickHouse; without it every test returns early.
#![allow(dead_code)]

use std::sync::Arc;

use chrono::{DateTime, Duration, TimeZone, Utc};
use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::{OcsfProfile, SchemaProfile, UdmProfile};
use serde_json::{json, Value};

const UDM_DDL: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../clickhouse/init.sql"));
const OCSF_DDL: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../clickhouse/ocsf/init.sql"));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Udm,
    Ocsf,
}

pub const BOTH: [Profile; 2] = [Profile::Udm, Profile::Ocsf];

/// Window start of every fixture: [T0, T0 + 1h).
pub fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap()
}

pub fn window() -> TimeRange {
    TimeRange { start: t0(), end: t0() + Duration::hours(1) }
}

pub struct Ch {
    client: clickhouse::Client,
    pub db: String,
}

/// Neutral fixture row; each profile maps it to its own columns.
#[derive(Clone)]
pub struct Event {
    pub minute: i64,
    pub user: &'static str,
    pub src_ip: &'static str,
    pub dest_ip: &'static str,
    pub dest_port: u16,
    pub status: &'static str,
    pub bytes_in: u64,
    pub tags: &'static [&'static str],
    pub message: &'static str,
    pub host: &'static str,
}

pub fn events() -> Vec<Event> {
    let e = |minute, user, src_ip, dest_ip, dest_port, status, bytes_in, tags, message, host| Event {
        minute, user, src_ip, dest_ip, dest_port, status, bytes_in, tags, message, host,
    };
    vec![
        e(0, "erin", "10.9.9.9", "10.0.0.7", 22, "200", 50, &[][..], "window start", "ws-5"),
        e(10, "Alice", "10.1.2.3", "10.0.0.5", 443, "404", 900, &["SeDebugPrivilege", "T1110"][..], "GET https://host/x", "ws-1"),
        e(20, "bob", "8.8.8.8", "203.0.113.9", 80, "7", 200, &["T1110"][..], "C:\\Windows\\System32\\cmd.exe", "ws-2"),
        e(30, "carol", "192.168.1.1", "172.16.5.5", 443, "4000", 300, &[][..], "plain", "ws-1"),
        e(40, "bob", "8.8.4.4", "198.51.100.1", 53, "500", 100, &["SeImpersonatePrivilege"][..], "dns", "ws-2"),
        // Exactly on the window end: outside a half-open [start, end).
        e(60, "dave", "10.5.5.5", "10.0.0.9", 443, "200", 1000, &[][..], "window end", "ws-9"),
    ]
}

impl Event {
    fn ts(&self) -> String {
        (t0() + Duration::minutes(self.minute)).format("%Y-%m-%d %H:%M:%S%.3f").to_string()
    }

    fn row(&self, profile: Profile, idx: usize) -> Value {
        match profile {
            Profile::Udm => json!({
                "timestamp": self.ts(), "source_type": "fixture", "user": self.user,
                "src_ip": self.src_ip, "dest_ip": self.dest_ip, "dest_port": self.dest_port,
                "status": self.status, "bytes_in": self.bytes_in,
                // UDM `tags` are lowercase at rest (the ClickHouse-table convention).
                "tags": self.tags.iter().map(|t| t.to_lowercase()).collect::<Vec<_>>(),
                "message": self.message, "src_host": self.host,
            }),
            Profile::Ocsf => json!({
                "timestamp": self.ts(), "source_type": "fixture", "class_uid": 4001,
                "metadata.uid": format!("uid-{idx:02}"), "actor.user.name": self.user,
                "src_endpoint.ip": self.src_ip, "dst_endpoint.ip": self.dest_ip,
                "dst_endpoint.port": self.dest_port, "status": self.status,
                "traffic.bytes_in": self.bytes_in, "resources.type": self.tags,
                // `resources` is a Nested structure: its arrays share one length.
                "resources.uid": self.tags.iter().map(|t| format!("r-{t}")).collect::<Vec<_>>(),
                "resources.name": self.tags.iter().map(|t| format!("n-{t}")).collect::<Vec<_>>(),
                "message": self.message, "device.hostname": self.host,
            }),
        }
    }
}

/// Neutral field name -> the profile's column.
pub fn f(profile: Profile, neutral: &str) -> &'static str {
    let pairs: &[(&str, &str, &str)] = &[
        ("user", "user", "actor.user.name"),
        ("src_ip", "src_ip", "src_endpoint.ip"),
        ("dest_ip", "dest_ip", "dst_endpoint.ip"),
        ("dest_port", "dest_port", "dst_endpoint.port"),
        ("status", "status", "status"),
        ("bytes_in", "bytes_in", "traffic.bytes_in"),
        ("tags", "tags", "resources.type"),
        ("message", "message", "message"),
        ("host", "src_host", "device.hostname"),
    ];
    let (_, udm, ocsf) = pairs.iter().find(|(n, _, _)| *n == neutral).unwrap_or_else(|| panic!("no field {neutral}"));
    match profile {
        Profile::Udm => udm,
        Profile::Ocsf => ocsf,
    }
}

/// Replace `{name}` placeholders with the profile's column names.
pub fn npl(profile: Profile, template: &str) -> String {
    let mut out = template.to_string();
    for name in ["user", "src_ip", "dest_ip", "dest_port", "status", "bytes_in", "tags", "message", "host"] {
        out = out.replace(&format!("{{{name}}}"), f(profile, name));
    }
    out
}

impl Ch {
    /// `None` when no disposable ClickHouse is configured.
    pub async fn connect(tag: &str) -> Option<Self> {
        let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL").ok()?;
        let mut client = nanosiem_core::db::clickhouse_transport::client().with_url(url);
        if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
            client = client.with_user(user);
        }
        if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
            client = client.with_password(password);
        }
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let ch = Self { client, db: format!("npl_wrong_answer_{tag}_{nanos}") };
        ch.exec(&format!("CREATE DATABASE {}", ch.db)).await;
        ch.exec(&table_ddl(UDM_DDL, "nanosiem.logs", &ch.db)).await;
        ch.exec(&table_ddl(OCSF_DDL, "nanosiem.ocsf_logs", &ch.db)).await;
        for profile in BOTH {
            let rows: Vec<String> = events().iter().enumerate().map(|(i, e)| e.row(profile, i).to_string()).collect();
            ch.insert(profile, &rows).await;
        }
        Some(ch)
    }

    pub async fn insert(&self, profile: Profile, rows: &[String]) {
        let table = match profile {
            Profile::Udm => "logs",
            Profile::Ocsf => "ocsf_logs",
        };
        self.exec(&format!(
            "INSERT INTO {}.{table} SETTINGS async_insert=0, input_format_skip_unknown_fields=0 FORMAT JSONEachRow\n{}",
            self.db,
            rows.join("\n")
        ))
        .await;
    }

    pub async fn drop(self) {
        self.exec(&format!("DROP DATABASE IF EXISTS {}", self.db)).await;
    }

    pub async fn exec(&self, sql: &str) {
        self.client
            .query(&sql.replace('?', "??"))
            .execute()
            .await
            .unwrap_or_else(|e| panic!("{e}\n--- SQL ---\n{sql}"));
    }

    pub async fn try_rows(&self, sql: &str) -> Result<Vec<Value>, String> {
        let mut cursor = self
            .client
            .query(&sql.replace('?', "??"))
            .fetch_bytes("JSONEachRow")
            .map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        while let Some(chunk) = cursor.next().await.map_err(|e| e.to_string())? {
            bytes.extend_from_slice(&chunk);
        }
        Ok(String::from_utf8(bytes)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect())
    }

    pub fn generator(&self, profile: Profile) -> ClickHouseSqlGenerator {
        match profile {
            Profile::Udm => ClickHouseSqlGenerator::with_table(format!("{}.logs", self.db))
                .with_profile(Arc::new(UdmProfile::new()) as Arc<dyn SchemaProfile>),
            Profile::Ocsf => ClickHouseSqlGenerator::with_table(format!("{}.ocsf_logs", self.db))
                .with_profile(Arc::new(OcsfProfile::new()) as Arc<dyn SchemaProfile>),
        }
    }

    pub fn sql(&self, profile: Profile, query: &str, range: &TimeRange) -> Result<String, String> {
        let parsed = parse_query(query).map_err(|e| format!("parse: {e}"))?;
        self.generator(profile).generate(&parsed, range).map_err(|e| format!("sqlgen: {e}"))
    }

    /// Generate with the production generator and execute; `Err` carries the
    /// stage that failed (parse / sqlgen / ClickHouse) and the SQL.
    pub async fn run(&self, profile: Profile, query: &str, range: &TimeRange) -> Result<Vec<Value>, String> {
        let sql = self.sql(profile, query, range)?;
        self.try_rows(&sql).await.map_err(|e| format!("clickhouse: {e}\n--- SQL ---\n{sql}"))
    }

    pub async fn rows(&self, profile: Profile, query: &str) -> Vec<Value> {
        self.run(profile, query, &window()).await.unwrap_or_else(|e| panic!("{profile:?} `{query}`: {e}"))
    }
}

/// One `CREATE TABLE` from the checked-in DDL, repointed at `db`, without its
/// TTL. Columns computed from dictionaries (enrichment / prevalence) become
/// type defaults: the suite never creates those dictionaries, and every other
/// column, index and projection stays as production ships it.
fn table_ddl(ddl: &str, table: &str, db: &str) -> String {
    let head = format!("CREATE TABLE IF NOT EXISTS {table}\n");
    let start = ddl.find(&head).unwrap_or_else(|| panic!("{table} not in DDL"));
    let body: String = ddl[start..]
        .lines()
        .filter(|l| !l.trim_start().starts_with("--") && !l.trim_start().starts_with("TTL "))
        .collect::<Vec<_>>()
        .join("\n");
    let open = body.find('(').unwrap();
    let close = matching_paren(&body, open);
    let columns: Vec<String> = split_top_level(&body[open + 1..close])
        .into_iter()
        .map(|col| if col.contains("dictGet") { dictionary_free(&col) } else { col })
        .collect();
    let tail = body[close..].split(';').next().unwrap();
    format!("{}{}{}", &body[..=open], columns.join(","), tail).replace("nanosiem.", &format!("{db}."))
}

fn dictionary_free(col: &str) -> String {
    let col = col.trim();
    let name_end = col[1..].find('`').unwrap() + 2;
    let rest = col[name_end..].trim_start();
    let mut depth = 0;
    let ty_end = rest
        .char_indices()
        .find(|&(_, c)| {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            c.is_whitespace() && depth == 0
        })
        .map_or(rest.len(), |(i, _)| i);
    let ty = &rest[..ty_end];
    format!("\n    {} {ty} DEFAULT defaultValueOfTypeName('{ty}')", &col[..name_end])
}

fn scan(body: &str, mut on: impl FnMut(usize, char, i32) -> bool) {
    let (mut depth, mut quote, mut escaped) = (0i32, None::<char>, false);
    for (i, c) in body.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '`' => quote = Some(c),
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if on(i, c, depth) {
            return;
        }
    }
}

fn matching_paren(body: &str, open: usize) -> usize {
    let mut close = None;
    scan(&body[open..], |i, c, depth| {
        let done = c == ')' && depth == 0;
        if done {
            close = Some(open + i);
        }
        done
    });
    close.expect("balanced DDL")
}

fn split_top_level(list: &str) -> Vec<String> {
    let (mut parts, mut from) = (Vec::new(), 0);
    scan(list, |i, c, depth| {
        if c == ',' && depth == 0 {
            parts.push(list[from..i].to_string());
            from = i + 1;
        }
        false
    });
    parts.push(list[from..].to_string());
    parts
}

/// A row's string value whatever JSON type ClickHouse picked for it.
pub fn s(row: &Value, key: &str) -> String {
    match &row[key] {
        Value::String(v) => v.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

pub fn column(rows: &[Value], key: &str) -> Vec<String> {
    rows.iter().map(|r| s(r, key)).collect()
}
