// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5356: the OCSF audit union reader shows each case audit event once,
//! as the right row. A new-style event (shared event id) is listed as its
//! OCSF copy. A legacy (pre-fix) event is listed as its UDM row, which is
//! canonical, and its copy is hidden unless the original is gone. Assertions
//! compare each listed row's identity (event time and message, which also
//! name the store), not only counts, through the full read, LIMIT/OFFSET
//! pages and the count. Runs the real reader SQL ([`rows_sql`] /
//! [`count_sql`]) against a disposable ClickHouse: it creates and drops its
//! own database.
//!
//! The rows are the shapes the writers produce: the OCSF copy is the
//! platform `AuditEvent::to_ocsf_event` row (what `ocsf_logs_raw_mv` stores
//! from it), and the UDM case row mirrors `CaseAuditEvent::to_parsed_log`
//! (enterprise) before and after NAN-5356.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --lib case_dedupe_live_tests -- --ignored
//! ```

use super::*;
use crate::audit::{AuditEvent, AuditSource};
use serde_json::{json, Value};

fn ch() -> clickhouse::Client {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    let mut client = crate::db::clickhouse_transport::client().with_url(url);
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        client = client.with_password(password);
    }
    client
}

/// One case action, as the case writer sees it.
struct CaseAction {
    case_id: Uuid,
    action: &'static str,
    actor: Uuid,
    alert_id: Option<Uuid>,
    at: DateTime<Utc>,
}

impl CaseAction {
    /// The case metadata of the UDM row (`CaseAuditEvent::to_parsed_log`).
    fn metadata(&self, event_id: Option<Uuid>) -> Value {
        let mut m = json!({
            "case_number": 7,
            "case_title": "Suspicious logins",
            "actor_id": self.actor.to_string(),
            "previous_status": null,
            "disposition": null,
            "assigned_to": null,
            "assigned_to_name": null,
            "alert_count": 2,
            "entity_count": 0,
            "grouping_type": null,
            "alert_id": self.alert_id.map(|a| a.to_string()),
            "entity_value": null,
            "entity_type": null,
            "related_case_id": null,
            "notes": null,
        });
        if let Some(id) = event_id {
            m["event_id"] = json!(id.to_string());
        }
        m
    }

    /// The OCSF copy (`CaseAuditEvent::to_platform_event`): `details` is the
    /// UDM metadata plus the case typeid, status and severity.
    fn platform_event(&self, event_id: Option<Uuid>, at: DateTime<Utc>) -> AuditEvent {
        let mut details = self.metadata(event_id);
        details["case_id"] = json!(crate::typeid::encode("case", &self.case_id));
        details["status"] = json!("open");
        details["severity"] = json!("high");
        let mut e = AuditEvent::builder(AuditSource::Case, self.action)
            .actor(Some(self.actor), Some("Dan".into()))
            .resource("case", Some(self.case_id), Some("Suspicious logins".into()))
            .details(details)
            .build();
        if let Some(id) = event_id {
            e.event_id = id;
        }
        e.occurred_at = at;
        e
    }
}

struct Store {
    client: clickhouse::Client,
    db: String,
}

impl Store {
    async fn new() -> Self {
        let client = ch();
        let db = format!("nan5356_{}", Uuid::now_v7().simple());
        let s = Self { client, db };
        s.exec(&format!("CREATE DATABASE {}", s.db)).await;
        s.exec(&format!(
            "CREATE TABLE {}.logs (id UUID, timestamp DateTime64(6, 'UTC'), source_type LowCardinality(String), \
             source String, `user` String, action String, src_ip String, user_agent String, status String, \
             severity String, session_id String, message String, metadata String) \
             ENGINE = MergeTree ORDER BY timestamp",
            s.db
        ))
        .await;
        s.exec(&format!(
            "CREATE TABLE {}.ocsf_logs (id UUID, timestamp DateTime64(3, 'UTC'), source_type LowCardinality(String), \
             message String, `actor.user.name` String, `api.operation` LowCardinality(String), \
             `api.service.name` LowCardinality(String), `src_endpoint.ip` String, \
             `http_request.user_agent` String, status_id Int32, unmapped JSON(max_dynamic_paths = 256)) \
             ENGINE = MergeTree ORDER BY timestamp",
            s.db
        ))
        .await;
        s
    }

    async fn exec(&self, sql: &str) {
        self.client.query(sql).execute().await.unwrap_or_else(|e| panic!("{sql}: {e}"));
    }

    /// The UDM case row: pre-fix (`event_id = None`, the case message) or
    /// post-fix (`metadata.event_id`).
    async fn udm_case(&self, a: &CaseAction, event_id: Option<Uuid>) -> Row {
        let message = format!("Case {} (CASE-7) {}: Suspicious logins [high] by Dan", a.case_id, a.action);
        let row = (a.at.timestamp_millis(), message.clone());
        self.client
            .query(&format!(
                "INSERT INTO {}.logs VALUES (generateUUIDv7(), fromUnixTimestamp64Micro(toInt64(?), 'UTC'), 'audit', \
                 'case', 'Dan', ?, '', '', 'open', 'high', ?, ?, ?)",
                self.db
            ))
            .bind(a.at.timestamp_micros())
            .bind(a.action)
            .bind(a.case_id.to_string())
            .bind(message)
            .bind(a.metadata(event_id).to_string())
            .execute()
            .await
            .unwrap();
        row
    }

    /// The UDM row of a platform event (`AuditEvent::to_parsed_log`); a
    /// pre-NAN-5346 row has no `metadata.event_id`.
    async fn udm_platform(&self, e: &AuditEvent, pre_5346: bool) {
        let mut log = e.to_parsed_log();
        if pre_5346 {
            log.metadata.as_object_mut().unwrap().remove("event_id");
        }
        self.client
            .query(&format!(
                "INSERT INTO {}.logs VALUES (generateUUIDv7(), fromUnixTimestamp64Micro(toInt64(?), 'UTC'), 'audit', \
                 ?, ?, ?, '', '', ?, '', ?, ?, ?)",
                self.db
            ))
            .bind(log.timestamp.timestamp_micros())
            .bind(log.source.unwrap_or_default())
            .bind(log.user.unwrap_or_default())
            .bind(log.action.unwrap_or_default())
            .bind(log.status.unwrap_or_default())
            .bind(log.session_id.unwrap_or_default())
            .bind(log.message)
            .bind(log.metadata.to_string())
            .execute()
            .await
            .unwrap();
    }

    /// The OCSF copy: row `id` = event id, timestamp = `event.time`.
    async fn ocsf(&self, e: &AuditEvent) -> Row {
        let row = e.to_ocsf_event(e.occurred_at);
        let visible = (e.occurred_at.timestamp_millis(), e.message());
        let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
        self.client
            .query(&format!(
                "INSERT INTO {}.ocsf_logs SELECT toUUID(?), fromUnixTimestamp64Milli(toInt64(?), 'UTC'), 'audit', \
                 ?, ?, ?, ?, '', '', toInt32(?), ?",
                self.db
            ))
            .bind(e.event_id.to_string())
            .bind(row["time"].as_i64().unwrap())
            .bind(s(&row["message"]))
            .bind(s(&row["actor"]["user"]["name"]))
            .bind(s(&row["api"]["operation"]))
            .bind(s(&row["api"]["service"]["name"]))
            .bind(row["status_id"].as_i64().unwrap())
            .bind(row["unmapped"].to_string())
            .execute()
            .await
            .unwrap();
        visible
    }

    /// The Audit API page `[offset, offset + limit)` over `[from, to]`, as
    /// (event time in ms, message), newest first.
    async fn page(&self, from: DateTime<Utc>, to: DateTime<Utc>, limit: u64, offset: u64) -> Vec<Row> {
        let (sql, binds) = rows_sql(&self.segments(from, to), &[]);
        let mut q = self.client.query(&sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        let rows: Vec<AuditRow> =
            q.bind(limit).bind(offset).fetch_all().await.unwrap_or_else(|e| panic!("{sql}: {e}"));
        rows.into_iter()
            .map(row_to_entry)
            .map(|e| (e.timestamp.timestamp_millis(), e.message))
            .collect()
    }

    fn segments(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<AuditSegment> {
        plan_sources(
            AuditStore::Ocsf,
            &format!("{}.logs", self.db),
            &format!("{}.ocsf_logs", self.db),
            from,
            Some(to),
        )
    }

    async fn count(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> u64 {
        let (sql, binds) = count_sql(&self.segments(from, to), &[]);
        let mut q = self.client.query(&sql);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        q.fetch_one::<CountRow>().await.unwrap_or_else(|e| panic!("{sql}: {e}")).count
    }

    /// Every row of `[from, to]`, checked three ways: one big page, 3-row
    /// pages through LIMIT/OFFSET, and the count. All must agree.
    async fn read(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<Row> {
        let all = self.page(from, to, 1000, 0).await;
        let mut paged = Vec::new();
        for offset in (0..all.len() as u64 + 3).step_by(3) {
            paged.extend(self.page(from, to, 3, offset).await);
        }
        assert_eq!(paged, all, "LIMIT/OFFSET pages differ from the full read");
        assert_eq!(self.count(from, to).await, all.len() as u64, "count differs from rows: {all:#?}");
        all
    }

    async fn drop(self) {
        self.exec(&format!("DROP DATABASE {}", self.db)).await;
    }
}

/// A visible audit row's identity: event time (ms) and message. The UDM
/// case row and the OCSF copy differ in both, so this names the event AND
/// the store it was read from.
type Row = (i64, String);

/// The expected rows, newest first (the reader's order).
fn newest_first(mut rows: Vec<Row>) -> Vec<Row> {
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    rows
}

fn t0() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_790_000_000, 0).unwrap()
}

fn ms(n: i64) -> chrono::Duration {
    chrono::Duration::milliseconds(n)
}

fn secs(n: i64) -> chrono::Duration {
    chrono::Duration::seconds(n)
}

/// Codex's scenario plus the other legacy shapes: legacy (pre-NAN-5356) case
/// UDM rows are canonical and always shown, their copies hidden; nothing is
/// paired, so a failed mirror never hides or swaps an event.
#[tokio::test]
#[ignore = "needs a disposable ClickHouse: NANOSIEM_TEST_CLICKHOUSE_URL"]
async fn legacy_case_rows_are_canonical_and_keep_their_identity() {
    let store = Store::new().await;
    let case_id = Uuid::now_v7();
    let actor = Uuid::now_v7();
    let act = |action, alert_id, at| CaseAction { case_id, action, actor, alert_id, at };
    let mut expected = Vec::new();

    // 1. Missing copy before a success (Codex's scenario): U1 and U2 share a
    //    fingerprint, U1's mirror write failed, U2's copy landed. Both UDM
    //    rows show with their own timestamps; the copy does not.
    let same = Uuid::now_v7();
    let u1 = act("alert_removed", Some(same), t0());
    let u2 = act("alert_removed", Some(same), t0() + ms(40));
    expected.push(store.udm_case(&u1, None).await);
    expected.push(store.udm_case(&u2, None).await);
    store.ocsf(&u2.platform_event(None, u2.at + ms(80))).await;

    // 2. Copy present for both (same fingerprint): the two UDM rows.
    let both = Uuid::now_v7();
    let v1 = act("alert_added", Some(both), t0() + secs(1));
    let v2 = act("alert_added", Some(both), t0() + secs(1) + ms(30));
    for v in [&v1, &v2] {
        expected.push(store.udm_case(v, None).await);
        store.ocsf(&v.platform_event(None, v.at + ms(80))).await;
    }

    // 3. Distinct fingerprints, quick, interleaved writes: both UDM rows.
    let w1 = act("alert_added", Some(Uuid::now_v7()), t0() + secs(2));
    let w2 = act("alert_added", Some(Uuid::now_v7()), t0() + secs(2) + ms(20));
    expected.push(store.udm_case(&w1, None).await);
    expected.push(store.udm_case(&w2, None).await);
    store.ocsf(&w1.platform_event(None, w1.at + ms(80))).await;
    store.ocsf(&w2.platform_event(None, w2.at + ms(85))).await;

    // 4. New-style events: shared id and timestamp, the OCSF copy is listed
    //    once, also two quick ones with the same content.
    for at in [t0() + secs(3), t0() + secs(3) + ms(5)] {
        let n = act("comment_added", None, at);
        let id = Uuid::now_v7();
        store.udm_case(&n, Some(id)).await;
        expected.push(store.ocsf(&n.platform_event(Some(id), n.at)).await);
    }

    // 5. Platform events: deduped on the event id, and a pre-NAN-5346 case
    //    handler event (no event id, source `case`) on (ms, message).
    let mut platform = AuditEvent::builder(AuditSource::Detection, "rule_created")
        .actor(Some(actor), Some("Dan".into()))
        .build();
    platform.occurred_at = t0() + secs(4);
    store.udm_platform(&platform, false).await;
    expected.push(store.ocsf(&platform).await);
    let mut handler = AuditEvent::builder(AuditSource::Case, "case_assigned")
        .actor(Some(actor), Some("Dan".into()))
        .resource("case", Some(case_id), Some("Suspicious logins".into()))
        .details(json!({"case_number": 7, "case_title": "Suspicious logins", "assigned_to": "x"}))
        .build();
    handler.occurred_at = t0() + secs(5);
    store.udm_platform(&handler, true).await;
    expected.push(store.ocsf(&handler).await);

    // 6. Orphan: the legacy original is gone (retention drift between the
    //    tables), so the copy is the only record and is shown.
    let orphan = act("resolved", None, t0() + secs(6));
    expected.push(store.ocsf(&orphan.platform_event(None, orphan.at + ms(80))).await);

    let rows = store.read(t0() - secs(1), t0() + secs(10)).await;
    store.drop().await;
    assert_eq!(rows, newest_first(expected), "{rows:#?}");
}

/// Window edges with a failed mirror next to a pair:
/// * a window ending between an original and its copy lists the original;
/// * a window starting between them lists neither (documented edge: the
///   original is just outside, its copy is hidden); widening it lists the
///   original once;
/// * a failed-mirror event next to the pair is always listed.
#[tokio::test]
#[ignore = "needs a disposable ClickHouse: NANOSIEM_TEST_CLICKHOUSE_URL"]
async fn legacy_case_window_edges_with_a_failed_mirror() {
    let store = Store::new().await;
    let case_id = Uuid::now_v7();
    let actor = Uuid::now_v7();
    let paired = CaseAction { case_id, action: "assigned", actor, alert_id: None, at: t0() };
    let failed = CaseAction { case_id, action: "assigned", actor, alert_id: None, at: t0() + ms(20) };
    let original = store.udm_case(&paired, None).await;
    let lone = store.udm_case(&failed, None).await;
    store.ocsf(&paired.platform_event(None, paired.at + ms(80))).await;

    let ends_between = store.read(t0() - secs(1), t0() + ms(50)).await;
    let starts_between = store.read(t0() + ms(50), t0() + secs(1)).await;
    let wide = store.read(t0() - secs(1), t0() + secs(1)).await;
    store.drop().await;

    assert_eq!(ends_between, newest_first(vec![original.clone(), lone.clone()]));
    assert_eq!(starts_between, Vec::<Row>::new(), "documented edge");
    assert_eq!(wide, newest_first(vec![original, lone]));
}
