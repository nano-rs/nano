// SPDX-License-Identifier: AGPL-3.0-or-later

//! Disposable loopback Postgres only: NANO_LOCAL_DETECT_TEST_PG.
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::finding_append::{
    FindingAppendRequest, FindingAppendResponse, FindingAppendTransport,
};
use nanosiem_lake_worker::part_ingest::finding_outbox::{drain_pass_trusted_local, DrainLogCache};
use nanosiem_lake_worker::part_ingest::ingest::{seed_schema, IngestConfig, Ingestor};
use nanosiem_lake_worker::part_ingest::SpoolQueue;
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use sqlx::postgres::PgPoolOptions;

const TENANT: &str = "00000000-0000-4000-8000-000000000001";
const OTHER: &str = "00000000-0000-4000-8000-000000000002";

struct Append<'a>(tokio::sync::Mutex<Ingestor<'a>>, i64);
#[async_trait::async_trait]
impl FindingAppendTransport for Append<'_> {
    async fn submit(
        &self,
        request: &FindingAppendRequest,
    ) -> anyhow::Result<FindingAppendResponse> {
        self.0
            .lock()
            .await
            .append_finding(
                FindingAppendRequest {
                    tenant_id: request.tenant_id.clone(),
                    writer_epoch: request.writer_epoch,
                    schema: request.schema.clone(),
                    parts: request.parts.clone(),
                    receipts: request.receipts.clone(),
                    deadline_unix_ms: request.deadline_unix_ms,
                },
                self.1,
            )
            .await
    }
}

#[tokio::test]
async fn open_schema_finding_drain_replays_without_hosted_principal() {
    let Ok(url) = std::env::var("NANO_LOCAL_DETECT_TEST_PG") else {
        return;
    };
    assert!(url.starts_with("postgres://postgres@127.0.0.1:") && url.ends_with("/localdetecttest"));
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    for sql in [
        include_str!("../../migrations/postgres/286_detection_finding_lake_outbox.sql"),
        include_str!("../../migrations/postgres/287_platform_audit_events.sql"),
        include_str!("../../migrations/postgres/290_platform_audit_lake_publication.sql"),
        include_str!("../../migrations/postgres/291_lake_publication_component_fences.sql"),
        "ALTER TABLE detection_finding_lake_outbox ADD COLUMN security_tenant_id uuid NOT NULL",
        include_str!("../../migrations/postgres/345_lean_finding_outbox_pending.sql"),
    ] {
        sqlx::raw_sql(sql).execute(&pool).await.unwrap();
    }
    let now = 1_790_444_800_000_i64;
    for tenant in [TENANT, OTHER] {
        let compact = serde_json::json!({"id":"finding-1","timestamp_us":now*1000,
            "entity":"alice@example.com","stamped_entity_type":"email","risk_score":75,
            "rule_id":"rule-1","rule_name":"fixture","severity":"high","origin_source_types":["auth"],"mitre_tactics":[]});
        let event = serde_json::json!({"class_uid":2004,"time":now,"metadata":{"uid":"finding-1",
            "tenant_uid":tenant,"log_source":"detections","log_name":"findings"},
            "is_alert":true,"risk_score":75,"finding_info":{"uid":"finding-1","types":["alert"],"uid_alt":"alert-1"}});
        sqlx::query("INSERT INTO detection_finding_lake_outbox (security_tenant_id,tenant_id,finding_id,compact_finding,ocsf_event) VALUES ($1,$2,'finding-1',$3,$4)")
            .bind(uuid::Uuid::parse_str(tenant).unwrap()).bind(tenant).bind(compact).bind(event).execute(&pool).await.unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let store = LocalObjectStore::new(dir.path().join("parts")).unwrap();
    let signer = LocalPartSigner::new("lab-local", SigningKey::from_bytes(&[7; 32])).unwrap();
    let queue = SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
    let ingest = Ingestor::open(
        IngestConfig::new(TENANT, dir.path().join("ingest")),
        &store,
        &store,
        &queue,
        &signer,
        signer.trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        now,
    )
    .await
    .unwrap();
    let append = Append(tokio::sync::Mutex::new(ingest), now);
    let mut cache = DrainLogCache::default();
    // A PostgreSQL failure AFTER the durable Add must be recovered by receipts.
    sqlx::raw_sql("CREATE FUNCTION fail_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$; CREATE TRIGGER fail_ack BEFORE UPDATE ON detection_finding_lake_outbox FOR EACH ROW EXECUTE FUNCTION fail_ack()")
        .execute(&pool).await.unwrap();
    assert!(drain_pass_trusted_local(
        &pool,
        &store,
        &signer,
        &signer.trusted(),
        TENANT,
        1,
        &append,
        &dir.path().join("work"),
        now,
        &|_, _| {},
        &mut cache
    )
    .await
    .is_err());
    let head = load_log(&store, TENANT).await.unwrap().head().unwrap().0;
    sqlx::query("DROP TRIGGER fail_ack ON detection_finding_lake_outbox")
        .execute(&pool)
        .await
        .unwrap();
    let mut restarted_cache = DrainLogCache::default();
    let pass = drain_pass_trusted_local(
        &pool,
        &store,
        &signer,
        &signer.trusted(),
        TENANT,
        1,
        &append,
        &dir.path().join("restart"),
        now,
        &|_, _| {},
        &mut restarted_cache,
    )
    .await
    .unwrap();
    assert_eq!(pass.committed, 1);
    assert_eq!(
        load_log(&store, TENANT).await.unwrap().head().unwrap().0,
        head,
        "replay must not append again"
    );
    let rows: Vec<(String,bool,bool)> = sqlx::query_as("SELECT tenant_id,event_published_at IS NOT NULL,risk_published_at IS NOT NULL FROM detection_finding_lake_outbox ORDER BY tenant_id")
        .fetch_all(&pool).await.unwrap();
    assert_eq!(
        rows,
        vec![
            (TENANT.to_string(), true, true),
            (OTHER.to_string(), false, false)
        ]
    );
    assert!(store
        .get(&format!("lake/parts/v1/tenant={OTHER}/log/head.json"))
        .await
        .unwrap()
        .is_none());
}
