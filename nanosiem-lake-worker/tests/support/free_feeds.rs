use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use nanosiem_core::platform_enrichment::{adapters::*, cache::*, publisher::Manifest, *};
use nanosiem_lake_worker::platform_stamping::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Cursor,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};
use uuid::Uuid;
pub const TENANT: &str = "00000000-0000-0000-0000-000000000001";
pub struct Fixture {
    pub _dir: tempfile::TempDir,
    pub writer: CacheWriter,
    pub reader: CacheReader,
    pub journal: Arc<Journal>,
    pub claim: Claim,
    pub ready: Vec<(Verified, Arc<Handle>)>,
}
pub struct Journal(pub Mutex<BTreeMap<String, Claim>>, pub Mutex<Claim>);
impl AdmissionJournal for Journal {
    fn pin_object(&self, _: Uuid, _: &str, _: &[Option<String>; 3]) -> anyhow::Result<()> {
        Ok(())
    }
    fn claim(
        &self,
        _: Uuid,
        uid: &str,
        source: &str,
        _: &[Option<String>; 3],
        _: &Value,
        _: &str,
    ) -> anyhow::Result<Claim> {
        let mut rows = self.0.lock().unwrap();
        Ok(rows
            .entry(uid.into())
            .or_insert_with(|| {
                let mut c = self.1.lock().unwrap().clone();
                c.vector.source_identity_sha256 = source.into();
                c.vector.admission_id = Uuid::new_v4();
                c
            })
            .clone())
    }
    fn decide(&self, _: Uuid, id: Uuid, d: &Decision) -> anyhow::Result<Decision> {
        let mut rows = self.0.lock().unwrap();
        let c = rows
            .values_mut()
            .find(|c| c.vector.admission_id == id)
            .unwrap();
        Ok(c.decision.get_or_insert_with(|| d.clone()).clone())
    }
    fn finalize(&self, o: &SignedOutput) -> anyhow::Result<SignedOutput> {
        let mut rows = self.0.lock().unwrap();
        let c = rows
            .values_mut()
            .find(|c| c.vector.admission_id == o.envelope.admission_id)
            .unwrap();
        Ok(c.output.get_or_insert_with(|| o.clone()).clone())
    }
}
struct NoGeo;
impl ExactLookup for NoGeo {
    fn lookup(
        &self,
        _: &SelectedFeedRevision,
        _: &str,
    ) -> std::result::Result<Option<GeoRecord>, StampReason> {
        Ok(None)
    }
}
impl Fixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let writer = CacheWriter::new(dir.path()).unwrap();
        let reader = CacheReader::new(dir.path());
        let now = Utc::now();
        let claim = Claim {
            refusal_details: Default::default(),
            mode: nanosiem_lake_worker::platform_stamping::runtime::Mode::Shadow,
            feed_times: BTreeMap::new(),
            vector: AdmissionRevisionVectorV1 {
                contract_version: 1,
                tenant_id: Uuid::from_u128(1),
                admission_id: Uuid::new_v4(),
                source_identity_sha256: "ab".repeat(32),
                admitted_at: now,
                catalog_revision: 1,
                feeds: vec![AdmissionFeed {
                    feed_id: "ipinfo_lite".into(),
                    deny_epoch: 0,
                    decision: AdmissionDecision::Unknown {
                        reason: StampReason::Missing,
                        artifact: None,
                        right: None,
                    },
                }],
            },
            legacy: [None, None, None],
            observation: json!({}),
            upstream_at: None,
            valid_until: None,
            freshness: FreshnessAtIngest::Unknown,
            decision: None,
            output: None,
        };
        Self {
            _dir: dir,
            writer,
            reader,
            journal: Arc::new(Journal(
                Mutex::new(BTreeMap::new()),
                Mutex::new(claim.clone()),
            )),
            claim,
            ready: vec![],
        }
    }
    pub fn install(&mut self, feed: &str, revision: i64, artifact: Artifact, age: Duration) {
        let now = self.claim.vector.admitted_at;
        let digest = hex::encode(Sha256::digest(&artifact.bytes));
        let key = SigningKey::from_bytes(&[7; 32]);
        let signed = Manifest {
            contract_version: 1,
            scope: "nano/platform-enrichment".into(),
            feed_id: feed.into(),
            revision,
            fencing_epoch: 1,
            bucket: "fixture".into(),
            object_key: format!("platform-enrichment/v1/{feed}/1/{revision}/{digest}.pack"),
            digest: digest.clone(),
            byte_count: artifact.bytes.len() as u64,
            uncompressed_bytes: artifact.bytes.len() as u64,
            mapped_bytes: artifact.bytes.len() as u64,
            row_count: artifact.rows,
            schema_version: 1,
            mapping_revision: 1,
            adapter_version: artifact.adapter.into(),
            license_revision: if feed == "synthient" {
                "sandbox-not-production"
            } else {
                "fixture-free-approval"
            }.into(),
            upstream_at: now - age,
            fetched_at: now - age,
            valid_until: now - age + Duration::days(1),
            signer_key_id: "fixture".into(),
        }
        .sign(&key)
        .unwrap();
        let keys = BTreeMap::from([("fixture".into(), key.verifying_key())]);
        signed.verify("fixture", 1, &keys, &artifact.bytes).unwrap();
        let v = Verified::verify(signed, "fixture", &keys).unwrap();
        self.writer
            .hydrate(&v, Cursor::new(artifact.bytes))
            .unwrap();
        let h = self.reader.acquire(&v).unwrap();
        self.ready.push((v, h));
        self.claim.vector.feeds.retain(|f| f.feed_id != feed);
        self.claim.vector.feeds.push(AdmissionFeed {
            feed_id: feed.into(),
            deny_epoch: 0,
            decision: AdmissionDecision::Selected {
                artifact: SelectedFeedRevision {
                    revision,
                    digest,
                    mapping_revision: 1,
                },
                right: AdmissionRight {
                    tier: if feed == "synthient" {
                        "sandbox"
                    } else {
                        "included"
                    }.into(),
                    grant_revision: 1,
                    entitlement_revision: 1,
                },
            },
        });
        self.claim
            .vector
            .feeds
            .sort_by(|a, b| a.feed_id.cmp(&b.feed_id));
        self.claim.feed_times.insert(
            feed.into(),
            FeedTime {
                upstream_at: Some(now - age),
                valid_until: Some(now - age + Duration::days(1)),
                freshness: FreshnessAtIngest::Fresh,
                hard_expiry_seconds: Some(86_400),
                freshness_seconds: Some(21_600),
            },
        );
        *self.journal.1.lock().unwrap() = self.claim.clone();
    }
    pub fn stamper(&self) -> ShadowStamper {
        ShadowStamper::new(
            self.journal.clone(),
            Arc::new(NoGeo),
            SigningKey::from_bytes(&[9; 32]),
            "fixture".into(),
        )
        .unwrap()
        .with_free_feeds(ReadyFree::new(
            self.ready.iter().filter(|(v, _)| v.feed_id() != "synthient").cloned().collect(),
        ).unwrap())
        .with_synthient(ReadySynthient::new(
            self.ready.iter().filter(|(v, _)| v.feed_id() == "synthient").cloned().collect(),
        ).unwrap())
    }
    pub fn stamp(&self, uid: &str, mut event: Value) -> Value {
        use nanosiem_lake_worker::iceberg::{normalize_event, EventKind, EventRow};
        event["metadata"]["uid"] = json!(uid);
        let source: [u8; 32] = Sha256::digest(serde_json::to_vec(&event).unwrap()).into();
        let stamper = self.stamper();
        let object = "aa".repeat(32);
        let mut session = stamper
            .begin(TENANT, uid, source, &mut event, [None, None, None], &object)
            .unwrap();
        session.decorate(&mut event).unwrap();
        let (_, value) = normalize_event(
            &EventRow {
                event_uid: uid.into(),
                event_kind: EventKind::Source,
                ocsf_event: event,
            },
            TENANT,
        )
        .unwrap();
        session.finalize(&value).unwrap();
        value
    }
}
pub fn event() -> Value {
    json!({"activity_id":1,"category_uid":4,"class_uid":4003,"type_uid":400301,"severity_id":1,"time":"2026-08-07T08:00:00Z","message":"fixture","raw_data":"fixture","raw_data_size":7,"metadata":{"log_name":"source","log_source":"WINDOWS_EVENT","uid":"fixture","tenant_uid":TENANT,"version":"1.9.0","product":{"name":"fixture","vendor_name":"nano"},"logged_time":1786089600000_i64},"src_endpoint":{"ip":"192.0.2.1","port":443},"dst_endpoint":{"ip":"2001:db8::1","port":8443},"query":{"hostname":"EXAMPLE.COM."}})
}
pub fn file_event() -> Value {
    let mut e = event();
    e.as_object_mut().unwrap().remove("query");
    e.as_object_mut().unwrap().remove("src_endpoint");
    e.as_object_mut().unwrap().remove("dst_endpoint");
    e["activity_id"] = json!(1);
    e["category_uid"] = json!(1);
    e["class_uid"] = json!(1001);
    e["type_uid"] = json!(100101);
    e["actor"] = json!({"user":{"name":"tester"}});
    e["device"] = json!({"type_id":6,"hostname":"fixture"});
    e["file"] = json!({"name":"fixture","type_id":1,"hashes":[{"algorithm_id":1,"value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]});
    e
}
pub fn http_event() -> Value {
    let mut e = event();
    e.as_object_mut().unwrap().remove("query");
    e["activity_id"] = json!(3);
    e["class_uid"] = json!(4002);
    e["type_uid"] = json!(400203);
    e["http_request"] =
        json!({"http_method":"GET","url":{"url_string":"https://example.com/Case?A=1"}});
    e
}

pub fn export(rows: &[(u64, &str, &str, &str, u32)], expiry: chrono::DateTime<Utc>) -> Artifact {
    let first = (Utc::now() - Duration::days(1))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let mut csv="# first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,confidence_level,expires_at\n".to_owned();
    if rows.is_empty() {
        csv.push_str("# of entries: 0\n");
    }
    for (id, value, kind, malware, confidence) in rows {
        csv.push_str(&format!(
            "{first},{id},{value},{kind},botnet_cc,{malware},{confidence},{}\n",
            expiry.to_rfc3339()
        ));
    }
    threatfox_csv(csv.as_bytes(), Utc::now()).unwrap()
}
