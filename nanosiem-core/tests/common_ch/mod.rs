// SPDX-License-Identifier: AGPL-3.0-or-later
//! Minimal ClickHouse HTTP harness for the observability SQL suites that run
//! generated SQL against a disposable ClickHouse. URL and credentials come from
//! the shared `nanosiem-test-db` helper (`CLICKHOUSE_TEST_URL`, or the older
//! `NANOSIEM_TEST_CLICKHOUSE_URL`; NAN-5967).
#![allow(dead_code)]

pub struct Ch {
    http: reqwest::Client,
    url: String,
    user: Option<String>,
    password: Option<String>,
}

impl Ch {
    pub fn from_env() -> Self {
        Self {
            http: reqwest::Client::new(),
            url: nanosiem_test_db::require_ch_url(),
            user: nanosiem_test_db::ch_user(),
            password: nanosiem_test_db::ch_password(),
        }
    }

    pub async fn run(&self, sql: &str) -> String {
        let mut req = self.http.post(&self.url).body(sql.to_owned());
        if let Some(user) = &self.user {
            req = req.header("X-ClickHouse-User", user);
        }
        if let Some(password) = &self.password {
            req = req.header("X-ClickHouse-Key", password);
        }
        let resp = req.send().await.expect("ClickHouse reachable");
        let status = resp.status();
        let body = resp.text().await.unwrap();
        assert!(status.is_success(), "{status}: {body}\n--- SQL ---\n{sql}");
        body
    }

    pub async fn rows(&self, sql: &str) -> Vec<serde_json::Value> {
        self.run(&format!("{sql}\nFORMAT JSONEachRow"))
            .await
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

/// The statement starting at `head`, comment lines stripped (comments may
/// themselves contain `;`, so drop them before looking for the terminator).
pub fn statement(sql: &str, head: &str) -> String {
    let start = sql.find(head).unwrap_or_else(|| panic!("{head} not in DDL"));
    sql[start..]
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// ClickHouse DateTime64 literal (microseconds).
pub fn ts(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}

/// Refuse to TRUNCATE unless the operator opted in (same guard as the PG suites).
pub fn assert_destructive_opt_in() {
    nanosiem_test_db::assert_destructive_opt_in("the test ClickHouse (this suite truncates tables)");
}
