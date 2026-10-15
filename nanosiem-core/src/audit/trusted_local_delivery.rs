// SPDX-License-Identifier: AGPL-3.0-or-later

//! Open single-tenant platform audit outbox → local Vector → bronze → cell.
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_EVENT_BYTES: usize = 128 * 1024;
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;

pub struct LocalAuditDelivery {
    pool: PgPool,
    tenant: Uuid,
    endpoint: reqwest::Url,
    token: Zeroizing<String>,
    http: reqwest::Client,
}

impl LocalAuditDelivery {
    /// Explicit trusted-local construction; the hosted runtime never uses it.
    /// The token comes from an installation-owned file and is never Debug/logged.
    pub fn new(pool: PgPool, tenant: Uuid, endpoint: &str, token: String) -> Result<Self, String> {
        if tenant.is_nil() || token.trim().len() < 32 || token.chars().any(char::is_control) {
            return Err("local audit requires a UUID tenant and a valid token".into());
        }
        let endpoint = reqwest::Url::parse(endpoint).map_err(|_| "invalid local audit endpoint")?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err("invalid local audit endpoint".into());
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| "local audit HTTP client")?;
        Ok(Self {
            pool,
            tenant,
            endpoint,
            token: Zeroizing::new(token),
            http,
        })
    }

    /// Create the pending-delivery partial index. Trusted-local only: migration
    /// 343 adds just the columns, because on hosted `lean_delivered_at` is never
    /// set and the index would cover every audit row forever. Idempotent; run
    /// once at worker boot before [`Self::deliver_once`]. A plain (not
    /// CONCURRENTLY) build: the open ledger is small and it runs before delivery.
    pub async fn prepare(&self) -> Result<(), String> {
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_platform_audit_open_lean_pending \
             ON platform_audit_events (tenant_id, occurred_at, event_id) \
             WHERE ocsf_event IS NOT NULL AND lean_delivered_at IS NULL AND lean_delivery_error IS NULL",
        )
        .execute(&self.pool)
        .await
        .map_err(|_| "local audit pending index create failed")?;
        Ok(())
    }

    /// Lock one bounded batch across the send and acknowledgement. A network or
    /// database failure leaves delivery eligible; stable event IDs let ingest
    /// absorb repeats. Invalid rows are quarantined so later audit rows progress.
    pub async fn deliver_once(&self) -> Result<usize, String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| "local audit begin failed")?;
        let rows = sqlx::query("SELECT event_id, ocsf_event FROM platform_audit_events \
            WHERE tenant_id=$1 AND ocsf_event IS NOT NULL AND lean_delivered_at IS NULL AND lean_delivery_error IS NULL \
            ORDER BY occurred_at,event_id LIMIT 200 FOR UPDATE SKIP LOCKED")
            .bind(self.tenant.to_string()).fetch_all(&mut *tx).await.map_err(|_| "local audit batch read failed")?;
        let mut body = String::new();
        let mut ids = Vec::new();
        for row in rows {
            let id: Uuid = row
                .try_get("event_id")
                .map_err(|_| "local audit identity decode failed")?;
            let event: Value = row
                .try_get("ocsf_event")
                .map_err(|_| "local audit event decode failed")?;
            let line = match audit_line(&event, self.tenant, id) {
                Ok(line) => line,
                Err(reason) => {
                    sqlx::query("UPDATE platform_audit_events SET lean_delivery_error=$1 WHERE tenant_id=$2 AND event_id=$3")
                        .bind(reason).bind(self.tenant.to_string()).bind(id).execute(&mut *tx).await
                        .map_err(|_| "local audit quarantine failed")?;
                    tracing::error!(event_id=%id, reason,"Local audit row quarantined");
                    continue;
                }
            };
            if body.len() + line.len() > MAX_BATCH_BYTES {
                break;
            }
            body.push_str(&line);
            ids.push(id);
        }
        if !ids.is_empty() {
            let response = self
                .http
                .post(self.endpoint.clone())
                .bearer_auth(self.token.as_str())
                .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
                .body(body)
                .send()
                .await
                .map_err(|_| "local audit send failed; batch retained")?;
            if !response.status().is_success() {
                return Err(format!(
                    "local audit refused ({}); batch retained",
                    response.status()
                ));
            }
            sqlx::query("UPDATE platform_audit_events SET lean_delivered_at=NOW(),lean_delivery_error=NULL \
                WHERE tenant_id=$1 AND event_id=ANY($2)")
                .bind(self.tenant.to_string()).bind(&ids).execute(&mut *tx).await.map_err(|_| "local audit acknowledgement failed")?;
        }
        tx.commit().await.map_err(|_| "local audit commit failed")?;
        Ok(ids.len())
    }
}

fn audit_line(event: &Value, tenant: Uuid, id: Uuid) -> Result<String, &'static str> {
    if !matches!(
        event.get("class_uid").and_then(Value::as_i64),
        Some(6003 | 3001 | 3002)
    ) {
        return Err("audit class must be 6003, 3001 or 3002");
    }
    if event
        .pointer("/metadata/tenant_uid")
        .and_then(Value::as_str)
        != Some(tenant.to_string().as_str())
        || event.pointer("/metadata/uid").and_then(Value::as_str) != Some(id.to_string().as_str())
        || event
            .pointer("/metadata/log_source")
            .and_then(Value::as_str)
            != Some("audit")
    {
        return Err("audit event identity or source differs");
    }
    if event
        .get("time")
        .and_then(Value::as_i64)
        .is_none_or(|time| time <= 0 || chrono::DateTime::from_timestamp_millis(time).is_none())
    {
        return Err("audit time must be valid positive milliseconds");
    }
    let mut line = serde_json::to_string(event).map_err(|_| "audit event serialization failed")?;
    if line.len() > MAX_EVENT_BYTES {
        return Err("audit event exceeds 128 KiB");
    }
    line.push('\n');
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_classes_preserve_identity_and_refuse_cross_tenant() {
        let tenant = Uuid::new_v4();
        let id = Uuid::new_v4();
        for class in [6003, 3001, 3002] {
            let mut event = serde_json::json!({"class_uid":class,"time":1700000000000_i64,
                "metadata":{"tenant_uid":tenant,"uid":id,"log_source":"audit"}});
            assert_eq!(
                serde_json::from_str::<Value>(&audit_line(&event, tenant, id).unwrap()).unwrap(),
                event
            );
            assert!(audit_line(&event, Uuid::new_v4(), id).is_err());
            assert!(audit_line(&event, tenant, Uuid::new_v4()).is_err());
            event["time"] = serde_json::json!(i64::MAX);
            assert!(audit_line(&event, tenant, id).is_err());
            event["time"] = serde_json::json!(1700000000000_i64);
            event["class_uid"] = serde_json::json!(2004);
            assert!(audit_line(&event, tenant, id).is_err());
        }
    }
    #[tokio::test]
    async fn delivery_acknowledges_only_successful_tenant_batches() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let Ok(url) = std::env::var("NANO_LOCAL_AUDIT_TEST_PG") else {
            return;
        };
        assert!(
            url.starts_with("postgres://postgres@127.0.0.1:") && url.ends_with("/localaudittest")
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        for sql in [
            include_str!("../../../migrations/postgres/287_platform_audit_events.sql"),
            include_str!("../../../migrations/postgres/290_platform_audit_lake_publication.sql"),
            include_str!("../../../migrations/postgres/343_open_lean_audit_delivery.sql"),
        ] {
            sqlx::raw_sql(sql).execute(&pool).await.unwrap();
        }
        let pending_index = || {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM pg_indexes WHERE indexname='idx_platform_audit_open_lean_pending'",
            )
            .fetch_one(&pool)
        };
        // The shared migration chain (hosted too) never creates the index.
        assert_eq!(pending_index().await.unwrap(), 0);
        let tenant = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut ids = Vec::new();
        for (t, class) in [
            (tenant, 6003),
            (tenant, 3001),
            (tenant, 3002),
            (other, 6003),
            (tenant, 2004),
        ] {
            let id = Uuid::new_v4();
            let event = serde_json::json!({"class_uid":class,"time":1700000000000_i64,
                "metadata":{"tenant_uid":t,"uid":id,"log_source":"audit"}});
            sqlx::query(
                "INSERT INTO platform_audit_events \
                (event_id,tenant_id,ocsf_event,action,source,success,status,message) \
                VALUES ($1,$2,$3,'fixture','fixture',true,'success','fixture')",
            )
            .bind(id)
            .bind(t.to_string())
            .bind(event)
            .execute(&pool)
            .await
            .unwrap();
            ids.push(id);
        }
        let server = MockServer::start().await;
        let token = "local-audit-fixture-token-32-characters";
        let delivery = LocalAuditDelivery::new(
            pool.clone(),
            tenant,
            &format!("{}/audit", server.uri()),
            token.into(),
        )
        .unwrap();
        delivery.prepare().await.unwrap();
        delivery.prepare().await.unwrap();
        assert_eq!(pending_index().await.unwrap(), 1);
        Mock::given(method("POST"))
            .and(path("/audit"))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        assert!(delivery.deliver_once().await.is_err());
        let delivered: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM platform_audit_events WHERE lean_delivered_at IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(delivered, 0);
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/audit"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        assert_eq!(delivery.deliver_once().await.unwrap(), 3);
        assert_eq!(delivery.deliver_once().await.unwrap(), 0);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let lines: Vec<Value> = String::from_utf8(requests[0].body.clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        for line in lines {
            assert!(audit_line(
                &line,
                tenant,
                line["metadata"]["uid"].as_str().unwrap().parse().unwrap()
            )
            .is_ok());
        }
        let states:Vec<(Uuid,bool,bool)>=sqlx::query_as("SELECT event_id,lean_delivered_at IS NOT NULL,lean_delivery_error IS NOT NULL FROM platform_audit_events")
            .fetch_all(&pool).await.unwrap();
        for (id, delivered, quarantined) in states {
            assert_eq!(delivered, ids[..3].contains(&id));
            assert_eq!(quarantined, id == ids[4]);
        }
    }
}
