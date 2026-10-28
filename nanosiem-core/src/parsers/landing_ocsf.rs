// SPDX-License-Identifier: AGPL-3.0-or-later

//! The lake storage stage for OCSF files dropped into the landing bucket
//! (NAN-3807).
//!
//! A sender that already maps to OCSF 1.9 (Tenzir, a custom pipeline) writes
//! files into `landing-ocsf-v1/` in the install's object store instead of
//! sending through Vector. The landing converter must write exactly the
//! bronze row Vector's last stage writes, so everything downstream (part
//! ingest with its enrichment and prevalence stamping, strict OCSF admission,
//! the uid window, parts, search) treats a landed row like any other.
//!
//! [`LandingOcsfStage`] does that by running Vector's own stage. It takes the
//! `ocsf_lake_storage_prepare` VRL out of the canonical object-lake sink text
//! (`vector_config::lake_ocsf_sink_text`, the generator every lean Vector
//! config comes from) and runs it with the vrl runtime, with the event
//! metadata the Vector lanes would stamp:
//!
//! * `%tenant_id`: the install's lake tenant;
//! * `%source_type` and `.source_type`: the route key of the source the
//!   landing folder belongs to (NAN-3806: the credential decides the source).
//!   Whatever the rows declare is replaced;
//! * `%ingress_transport`: [`LANDING_INGRESS_TRANSPORT`];
//! * `%nano_credential_id`: the source's landing credential id;
//! * `%nano_event_key`: `<sha256 of the file>:<row ordinal>`, the same shape
//!   the edge Worker's signed event keys take, so a reconverted or re-uploaded
//!   file derives the same uids for rows that carry none.
//!
//! The VRL then stamps metadata, keeps or mints `metadata.uid`, picks the
//! bronze shard and applies the fixed bronze row contract
//! ([`super::lake_bronze_row`]). Nothing here re-implements that logic, so it
//! cannot drift from Vector's.
//!
//! NAN-4675: a Vector-less (hosted Tenzir) tenant has no Vector, so the
//! platform delivers its platform audit through its bucket drop, under the
//! platform-owned landing source whose route key is
//! [`PLATFORM_AUDIT_ROUTE_KEY`] (`audit`). Vector runs every delivered audit
//! line through the base's `audit` plumbing lane BEFORE this stage (tenant,
//! class and product guard, the NAN-3304 null anchors, `unmapped` as one JSON
//! string). The landing stage runs that same lane VRL
//! ([`AUDIT_LANE_VRL`]) first for that route key, so a landed audit row is
//! byte-for-byte the row a Vector tenant writes, and a row the lane refuses
//! is dropped exactly as Vector drops it.

use chrono::{DateTime, Utc};
use std::sync::Arc;
use vrl::compiler::runtime::{Runtime, Terminate};
use vrl::compiler::state::RuntimeState;
use vrl::compiler::{Program, TargetValue, TimeZone};
use vrl::value::{ObjectMap, Secrets, Value as VrlValue};

use super::lake_bronze_row::{BRONZE_EVENT_COLUMN, BRONZE_TIME_COLUMN};
use super::tenant_bundle::platform_audit_lane::{AUDIT_LANE_VRL, AUDIT_SLUG};

/// NAN-4675: the route key of the platform audit landing source. Rows landed
/// under it cross the platform `audit` lane ([`AUDIT_LANE_VRL`]) before the
/// storage stage, exactly as Vector routes `source_type = audit`.
pub const PLATFORM_AUDIT_ROUTE_KEY: &str = AUDIT_SLUG;

/// The ingress lane stamped on landed rows (`metadata.ingress_transport`).
/// A member of the lake's closed lane list (`is_platform_ingress_transport`).
pub const LANDING_INGRESS_TRANSPORT: &str = "landing_bucket";

/// The Vector environment reference the stage reads its shard count from.
const BRONZE_SHARDS_REF: &str = "${NANO_LAKE_BRONZE_SHARDS:-1}";
const STAGE: &str = "ocsf_lake_storage_prepare";
/// Bronze key helper the stage sets (stripped by the sink's `except_fields`).
const PARTITION_FIELD: &str = "_nano_bronze_partition";

/// Who sent an event and how: the metadata the Vector lanes stamp.
#[derive(Debug, Clone)]
pub struct StageContext<'a> {
    /// The install's lake tenant (lowercased by the stage).
    pub tenant_id: &'a str,
    /// The bound source's route key. It becomes `metadata.log_source`.
    pub source_type: &'a str,
    /// The source's landing credential id (a lowercase UUID).
    pub credential_id: &'a str,
    /// `<64 hex>:<ordinal>`: the deterministic uid key for rows without one.
    pub event_key: Option<String>,
}

/// One row exactly as Vector's bronze sink receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BronzeRow {
    /// `""` or `shard=N/`, the key segment before `tenant_id=`.
    pub partition: String,
    /// The `time` column, as microseconds since the epoch (UTC).
    pub time_micros: i64,
    /// The `_nano_bronze_event` column: the OCSF row minus `time`, as JSON.
    pub event_json: String,
    /// The row's `metadata.uid` (for receipts and logs).
    pub uid: String,
}

/// Why the stage refused an event. Messages never quote event values.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StageError {
    /// The VRL aborted (Vector would drop the event).
    #[error("the lake storage stage dropped the event")]
    Aborted,
    /// The VRL failed at runtime (Vector would drop the event).
    #[error("the lake storage stage failed")]
    Failed,
    /// The stage produced a row without the bronze contract's columns.
    #[error("the lake storage stage produced no bronze row: {0}")]
    Shape(&'static str),
}

/// `ocsf_lake_storage_prepare`, compiled once and shared by every request,
/// with the platform `audit` lane that precedes it for
/// [`PLATFORM_AUDIT_ROUTE_KEY`] (NAN-4675). Cloning is cheap (the compiled
/// programs are shared), so a converter can hand the stage to a blocking
/// conversion task (NAN-4682).
#[derive(Clone)]
pub struct LandingOcsfStage {
    program: Arc<Program>,
    audit_lane: Arc<Program>,
}

/// NAN-4682: runs the stage over many rows with one VRL [`Runtime`], cleared
/// after every row (as Vector's remap does), instead of a new runtime per
/// row. Each row sees a fresh runtime state, so the output is identical to
/// [`LandingOcsfStage::prepare`].
pub struct StageRunner<'s> {
    stage: &'s LandingOcsfStage,
    runtime: Runtime,
}

impl StageRunner<'_> {
    /// [`LandingOcsfStage::prepare`] on this runner's runtime.
    pub fn prepare(&mut self, event: serde_json::Value, ctx: &StageContext<'_>) -> Result<BronzeRow, StageError> {
        self.stage.prepare_in(&mut self.runtime, event, ctx)
    }
}

impl std::fmt::Debug for LandingOcsfStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LandingOcsfStage").finish_non_exhaustive()
    }
}

/// The stage's VRL, from the canonical lake sink text, with Vector's
/// `${NANO_LAKE_BRONZE_SHARDS:-1}` resolved to `bronze_shards`.
pub fn storage_prepare_vrl(bronze_shards: u32) -> Result<String, String> {
    if !(1..=128).contains(&bronze_shards) {
        return Err("bronze shard count must be 1 to 128".into());
    }
    let text = super::vector_config::lake_ocsf_sink_text();
    if text.matches(BRONZE_SHARDS_REF).count() != 1 {
        return Err(format!("{STAGE} no longer reads {BRONZE_SHARDS_REF} exactly once"));
    }
    let text = text.replace(BRONZE_SHARDS_REF, &bronze_shards.to_string());
    // Vector interpolates `${VAR:-default}` over the whole file before parsing
    // it. Only the stage's VRL is used here, and its one reference is resolved
    // above; the sink's references just need a parseable stand-in.
    let env_ref = regex::Regex::new(r"\$\{[A-Z0-9_]+(?::-([^}]*))?\}").expect("static regex");
    let text = env_ref.replace_all(&text, |c: &regex::Captures<'_>| {
        c.get(1).map_or("0", |d| d.as_str()).to_string()
    });
    let doc: toml::Table = text
        .parse()
        .map_err(|e| format!("lake sink text is not TOML: {e}"))?;
    let source = doc
        .get("transforms")
        .and_then(|t| t.get(STAGE))
        .and_then(|t| t.get("source"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("lake sink text has no {STAGE} source"))?;
    if source.contains("${") {
        return Err(format!("{STAGE} reads an environment reference this stage does not resolve"));
    }
    Ok(source.to_string())
}

impl LandingOcsfStage {
    /// Compile the stage for an install with `bronze_shards` bronze prefixes.
    pub fn new(bronze_shards: u32) -> Result<Self, String> {
        let source = storage_prepare_vrl(bronze_shards)?;
        Self::compile(&source)
    }

    /// Bind the canonical stage's clock to a retained millisecond timestamp.
    /// Native durable retries must pass this same timestamp to the common
    /// converter as well. This pure factory supplies no source authority.
    pub fn new_at(bronze_shards: u32, received_at: DateTime<Utc>) -> Result<Self, String> {
        let millis = received_at.timestamp_millis();
        if millis <= 0 {
            return Err("landing conversion clock must be positive".into());
        }
        let source = storage_prepare_vrl(bronze_shards)?;
        // Bind event and final bronze-time fallbacks plus processed/logged
        // time. Refuse canonical-stage drift instead of retaining any clock.
        if source.matches("now()").count() != 3
            || source.matches("event_time = now()").count() != 1
            || source.matches("bronze_time = now()").count() != 1
            || source
                .matches("processed_time = to_unix_timestamp(now(), unit: \"milliseconds\")")
                .count()
                != 1
        {
            return Err("landing canonical clock shape changed".into());
        }
        let clock = format!("from_unix_timestamp!({millis}, unit: \"milliseconds\")");
        Self::compile(&source.replace("now()", &clock))
    }

    fn compile(source: &str) -> Result<Self, String> {
        let compiled =
            super::vrl_guard::compile(source, &vrl::stdlib::all()).map_err(|e| e.render(source))?;
        // The lane reads no clock, so `new_at` needs no rewrite of it.
        let audit_lane = super::vrl_guard::compile(AUDIT_LANE_VRL, &vrl::stdlib::all())
            .map_err(|e| e.render(AUDIT_LANE_VRL))?;
        Ok(Self {
            program: Arc::new(compiled.program),
            audit_lane: Arc::new(audit_lane.program),
        })
    }

    /// NAN-4675: the platform `audit` lane, as Vector runs it on a delivered
    /// line (`.message` holds the line, `%tenant_id` the cell's tenant). Its
    /// output is the `{event, timestamp, source_type}` row the storage stage
    /// receives from that lane.
    fn run_audit_lane(
        &self,
        runtime: &mut Runtime,
        event: serde_json::Value,
        metadata: &ObjectMap,
    ) -> Result<VrlValue, StageError> {
        let line = serde_json::to_string(&event).map_err(|_| StageError::Failed)?;
        let mut envelope = ObjectMap::new();
        envelope.insert("message".into(), VrlValue::from(line));
        envelope.insert("source_type".into(), VrlValue::from(PLATFORM_AUDIT_ROUTE_KEY));
        let mut target = TargetValue {
            value: VrlValue::Object(envelope),
            metadata: VrlValue::Object(metadata.clone()),
            secrets: Secrets::new(),
        };
        let resolved = runtime.resolve(&mut target, &self.audit_lane, &TimeZone::Local);
        runtime.clear();
        match resolved {
            Ok(_) => Ok(target.value),
            Err(Terminate::Abort(_)) => Err(StageError::Aborted),
            Err(Terminate::Error(_) | Terminate::Interrupted) => Err(StageError::Failed),
        }
    }

    /// A runner that reuses one VRL runtime across rows (NAN-4682).
    pub fn runner(&self) -> StageRunner<'_> {
        StageRunner { stage: self, runtime: Runtime::new(RuntimeState::default()) }
    }

    /// Run the stage on one OCSF event (a JSON object) sent by `ctx`.
    pub fn prepare(
        &self,
        event: serde_json::Value,
        ctx: &StageContext<'_>,
    ) -> Result<BronzeRow, StageError> {
        self.runner().prepare(event, ctx)
    }

    fn prepare_in(
        &self,
        runtime: &mut Runtime,
        event: serde_json::Value,
        ctx: &StageContext<'_>,
    ) -> Result<BronzeRow, StageError> {
        let mut metadata = ObjectMap::new();
        for (key, value) in [
            ("tenant_id", ctx.tenant_id),
            ("source_type", ctx.source_type),
            ("ingress_transport", LANDING_INGRESS_TRANSPORT),
            ("nano_credential_id", ctx.credential_id),
        ] {
            metadata.insert(key.into(), VrlValue::from(value));
        }
        if let Some(key) = &ctx.event_key {
            metadata.insert("nano_event_key".into(), VrlValue::from(key.as_str()));
        }
        // The Vector lanes hand the stage `{event, source_type}`; the
        // folder's source wins over anything inside the event. The platform
        // audit source first crosses Vector's own `audit` lane (NAN-4675).
        let envelope = if ctx.source_type == PLATFORM_AUDIT_ROUTE_KEY {
            self.run_audit_lane(runtime, event, &metadata)?
        } else {
            let mut envelope = ObjectMap::new();
            envelope.insert("event".into(), VrlValue::from(event));
            envelope.insert("source_type".into(), VrlValue::from(ctx.source_type));
            VrlValue::Object(envelope)
        };
        let mut target = TargetValue {
            value: envelope,
            metadata: VrlValue::Object(metadata),
            secrets: Secrets::new(),
        };
        let resolved = runtime.resolve(&mut target, &self.program, &TimeZone::Local);
        // Every row starts from an empty runtime state, as with a new runtime.
        runtime.clear();
        match resolved {
            Ok(_) => {}
            Err(Terminate::Abort(_)) => return Err(StageError::Aborted),
            Err(Terminate::Error(_) | Terminate::Interrupted) => return Err(StageError::Failed),
        }
        bronze_row(target.value)
    }
}

fn bronze_row(value: VrlValue) -> Result<BronzeRow, StageError> {
    let VrlValue::Object(mut row) = value else {
        return Err(StageError::Shape("row is not an object"));
    };
    let partition = match row.remove(PARTITION_FIELD) {
        Some(VrlValue::Bytes(bytes)) => String::from_utf8(bytes.to_vec())
            .map_err(|_| StageError::Shape("partition is not UTF-8"))?,
        None => String::new(),
        Some(_) => return Err(StageError::Shape("partition is not a string")),
    };
    let time: DateTime<Utc> = match row.remove(BRONZE_TIME_COLUMN) {
        Some(VrlValue::Timestamp(time)) => time,
        _ => return Err(StageError::Shape("time is not a timestamp")),
    };
    let event_json = match row.remove(BRONZE_EVENT_COLUMN) {
        Some(VrlValue::Bytes(bytes)) => String::from_utf8(bytes.to_vec())
            .map_err(|_| StageError::Shape("event is not UTF-8"))?,
        _ => return Err(StageError::Shape("event column is missing")),
    };
    if !row.is_empty() {
        return Err(StageError::Shape("row has columns outside the bronze contract"));
    }
    let uid = serde_json::from_str::<serde_json::Value>(&event_json)
        .ok()
        .and_then(|event| event.pointer("/metadata/uid").and_then(|v| v.as_str()).map(str::to_owned))
        .ok_or(StageError::Shape("event has no metadata.uid"))?;
    Ok(BronzeRow {
        partition,
        time_micros: time.timestamp_micros(),
        event_json,
        uid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const TENANT: &str = "8e3fd5b9-af91-4ad6-8092-97a192ee79ab";
    const CREDENTIAL: &str = "1b84f015-b560-433b-8bb6-ed4e39f48334";

    fn ctx(key: Option<&str>) -> StageContext<'static> {
        StageContext {
            tenant_id: TENANT,
            source_type: "tenzir_sysmon",
            credential_id: CREDENTIAL,
            event_key: key.map(str::to_owned),
        }
    }

    fn sysmon(uid: Option<&str>) -> Value {
        let mut event = json!({
            "class_uid": 1007, "category_uid": 1, "activity_id": 1, "type_uid": 100701,
            "severity_id": 1, "time": 1_791_975_595_105_i64,
            "message": "Process launched: cmd.exe /c echo x",
            "raw_data": "{\"EventID\":1}",
            "source_type": "spoofed",
            "metadata": {
                "version": "1.9.0", "log_source": "spoofed", "tenant_uid": "other-tenant",
                "nano_credential_id": "00000000-0000-4000-8000-000000000009",
                "product": {"name": "Sysmon", "vendor_name": "Microsoft"}
            },
            "device": {"hostname": "wks-01", "type_id": 0},
            "process": {"pid": 4000, "cmd_line": "cmd.exe /c echo x"}
        });
        if let Some(uid) = uid {
            event["metadata"]["uid"] = json!(uid);
        }
        event
    }

    fn event_of(row: &BronzeRow) -> Value {
        serde_json::from_str(&row.event_json).unwrap()
    }

    #[test]
    fn the_stage_is_vectors_own_vrl_with_the_shard_count_resolved() {
        let vrl = storage_prepare_vrl(1).unwrap();
        assert!(vrl.contains("bronze_shards = 1\n"));
        assert!(!vrl.contains("${"), "every Vector env reference is resolved");
        assert!(vrl.contains(super::super::lake_bronze_row::LAKE_BRONZE_ROW_MARKER));
        assert!(storage_prepare_vrl(0).is_err());
        assert!(storage_prepare_vrl(129).is_err());
    }

    #[test]
    fn the_token_decides_source_tenant_and_credential() {
        let stage = LandingOcsfStage::new(1).unwrap();
        let row = stage.prepare(sysmon(Some("2110bb68-d408-488a-b715-6e3e339404da")), &ctx(None)).unwrap();
        assert_eq!(row.partition, "");
        assert_eq!(row.time_micros, 1_791_975_595_105_000);
        let event = event_of(&row);
        let metadata = &event["metadata"];
        assert_eq!(metadata["log_source"], "tenzir_sysmon");
        assert_eq!(metadata["tenant_uid"], TENANT);
        assert_eq!(metadata["nano_credential_id"], CREDENTIAL);
        assert_eq!(metadata["ingress_transport"], LANDING_INGRESS_TRANSPORT);
        assert_eq!(metadata["version"], "1.9.0");
        assert_eq!(event["class_uid"], 1007);
        assert_eq!(event["raw_data_size"], 13);
        assert!(event.get("time").is_none(), "time is its own column");
    }

    #[test]
    fn a_sender_uid_is_kept_and_a_missing_one_follows_the_event_key() {
        let stage = LandingOcsfStage::new(1).unwrap();
        // A sender uid that is not a bare random UUIDv4 is the event's own id.
        let kept = stage.prepare(sysmon(Some("sysmon:wks-01:900000")), &ctx(Some(&format!("{}:0", "a".repeat(64))))).unwrap();
        assert_eq!(kept.uid, "sysmon:wks-01:900000");
        // No uid: the file key derives the same uid on every reconversion.
        let key = format!("{}:7", "b".repeat(64));
        let first = stage.prepare(sysmon(None), &ctx(Some(&key))).unwrap();
        let again = stage.prepare(sysmon(None), &ctx(Some(&key))).unwrap();
        assert_eq!(first.uid, again.uid);
        assert_eq!(&first.uid[14..15], "8", "derived uids are UUIDv8-shaped");
        // No uid and no key: a random uid, never a content-derived one.
        let a = stage.prepare(sysmon(None), &ctx(None)).unwrap();
        let b = stage.prepare(sysmon(None), &ctx(None)).unwrap();
        assert_ne!(a.uid, b.uid);
    }

    /// NAN-4682: one reused runtime (cleared per row) gives every row exactly
    /// what a fresh runtime gives, across accepted and dropped rows.
    #[test]
    fn a_reused_runner_matches_a_fresh_runtime_per_row() {
        let received = DateTime::<Utc>::from_timestamp_millis(1_792_843_200_123).unwrap();
        let stage = LandingOcsfStage::new_at(4, received).unwrap();
        let mut runner = stage.runner();
        let mut empty_tenant = ctx(Some("k:1"));
        empty_tenant.tenant_id = "";
        for i in 0..24 {
            let uid = (i % 3 == 0).then(|| format!("sysmon:wks-01:{i}"));
            let key = format!("{}:{i}", "c".repeat(64));
            let context = if i == 7 { empty_tenant.clone() } else { ctx(Some(&key)) };
            let mut event = sysmon(uid.as_deref());
            if i == 11 {
                event = json!("not an object");
            }
            assert_eq!(runner.prepare(event.clone(), &context), stage.prepare(event, &context), "row {i}");
        }
    }

    #[test]
    fn shards_route_by_uid() {
        let stage = LandingOcsfStage::new(4).unwrap();
        let row = stage.prepare(sysmon(Some("sysmon:wks-01:900000")), &ctx(None)).unwrap();
        assert!(row.partition.starts_with("shard=") && row.partition.ends_with('/'));
        let again = stage.prepare(sysmon(Some("sysmon:wks-01:900000")), &ctx(None)).unwrap();
        assert_eq!(row.partition, again.partition);
    }

    /// NAN-4320: a detection bound to a landing source matches the rows that
    /// source lands. The shared runtime pins every scan of a rule to its
    /// bound route slug on `metadata.log_source` (`pin_detection_query`) and
    /// filters on nothing Vector-only: a landed row (stamped
    /// `ingress_transport = landing_bucket`) is selected by its route key.
    #[test]
    fn a_rule_bound_to_the_landing_source_matches_landed_rows() {
        use crate::query::{parse_query, Query, SearchExpr};
        use crate::search::evaluate_condition_on_json;
        use crate::search::query_processing::{pin_detection_query, LAKE_SOURCE_FIELD};
        fn base(query: &Query) -> &SearchExpr {
            match query {
                Query::Search(expression) => expression,
                Query::Piped { source, .. } => base(source),
            }
        }
        let matches = |rule: &str, bound: &str, row: &Value| {
            let pinned = pin_detection_query(rule, bound, LAKE_SOURCE_FIELD).unwrap();
            evaluate_condition_on_json(base(&parse_query(&pinned.query).unwrap()), row)
        };
        let stage = LandingOcsfStage::new(1).unwrap();
        let landed = event_of(&stage.prepare(sysmon(None), &ctx(None)).unwrap());
        assert_eq!(landed["metadata"]["ingress_transport"], LANDING_INGRESS_TRANSPORT);
        // The rule names its landing source, or names none and is pinned to it.
        assert!(matches(r#"metadata.log_source="tenzir_sysmon" AND class_uid=1007"#, "tenzir_sysmon", &landed));
        assert!(matches("class_uid=1007 AND device.hostname=\"wks-01\"", "tenzir_sysmon", &landed));
        assert!(!matches("class_uid=3002", "tenzir_sysmon", &landed), "the rule body still decides");
        // Bound to another source, the landed row is out of scope.
        assert!(!matches("class_uid=1007", "apache_access", &landed));
    }

    #[test]
    fn an_empty_tenant_is_dropped_like_vector_drops_it() {
        let stage = LandingOcsfStage::new(1).unwrap();
        let mut context = ctx(None);
        context.tenant_id = "";
        // The stage falls back to NANO_TENANT_ID; with none set it aborts.
        if std::env::var("NANO_TENANT_ID").map(|v| v.is_empty()).unwrap_or(true) {
            assert_eq!(stage.prepare(sysmon(None), &context), Err(StageError::Aborted));
        }
    }

    #[test]
    fn retained_clock_controls_processing_and_missing_time_without_sender_override() {
        let received = DateTime::<Utc>::from_timestamp_millis(1_792_843_200_123).unwrap();
        let stage = LandingOcsfStage::new_at(1, received).unwrap();
        let mut event = sysmon(None);
        event.as_object_mut().unwrap().remove("time");
        event["metadata"]["processed_time"] = json!(1);
        event["metadata"]["logged_time"] = json!(2);
        let context = ctx(Some("retained-clock:0"));
        let row = stage.prepare(event.clone(), &context).unwrap();
        assert_eq!(row.time_micros, received.timestamp_micros());
        assert_eq!(row, stage.prepare(event.clone(), &context).unwrap());
        let prepared = event_of(&row);
        assert_eq!(
            prepared["metadata"]["processed_time"],
            received.timestamp_millis()
        );
        assert_eq!(
            prepared["metadata"]["logged_time"],
            received.timestamp_millis()
        );
        // A supplied event time remains independent of the receiver clock.
        event["time"] = json!(received.timestamp_millis() - 10_000);
        assert_eq!(
            stage.prepare(event, &context).unwrap().time_micros,
            received.timestamp_micros() - 10_000_000
        );
    }

    #[test]
    fn fixed_clock_factory_refuses_invalid_clock_and_shard_inputs() {
        let received = DateTime::<Utc>::from_timestamp_millis(1_792_843_200_123).unwrap();
        for millis in [0, -1] {
            assert!(
                LandingOcsfStage::new_at(
                    1,
                    DateTime::<Utc>::from_timestamp_millis(millis).unwrap()
                )
                .is_err()
            );
        }
        for shards in [0, 129] {
            assert!(LandingOcsfStage::new_at(shards, received).is_err());
        }
    }

    /// NAN-4675: platform audit landed by a Vector-less tenant.
    mod platform_audit {
        use super::*;
        use crate::parsers::tenant_bundle::{archive, platform_audit_lane};

        const AUDIT_TENANT: &str = "11111111-1111-4111-8111-111111111111";
        const OTHER_TENANT: &str = "22222222-2222-4222-8222-222222222222";
        const EVENT_ID: &str = "018f6a1e-0d2b-7c3a-9e4f-5a6b7c8d9e0f";

        /// The mirror the control plane stores and delivers
        /// (`AuditEvent::to_ocsf_event_for_lake`): a system actor with no
        /// client, so `src_endpoint` / `actor.user` are null-only (NAN-3304).
        fn audit_event(tenant: &str) -> Value {
            let event = crate::audit::AuditEvent::builder(crate::audit::AuditSource::Identity, "identity_sync_completed")
                .success(true)
                .build();
            let at = chrono::DateTime::parse_from_rfc3339("2026-10-21T06:02:00.123Z").unwrap().with_timezone(&Utc);
            event.to_ocsf_event_for_lake(at, uuid::Uuid::parse_str(EVENT_ID).unwrap(), tenant)
        }

        fn audit_ctx() -> StageContext<'static> {
            StageContext {
                tenant_id: AUDIT_TENANT,
                source_type: PLATFORM_AUDIT_ROUTE_KEY,
                credential_id: CREDENTIAL,
                event_key: Some(format!("{}:0", "a".repeat(64))),
            }
        }

        /// Fields Vector's and landing's rows legitimately differ in: the
        /// ingress lane and its credential, and the processing clocks.
        fn comparable(mut row: Value) -> Value {
            if let Some(metadata) = row["metadata"].as_object_mut() {
                for key in ["ingress_transport", "nano_credential_id", "processed_time", "logged_time"] {
                    metadata.remove(key);
                }
            }
            row
        }

        #[test]
        fn the_route_key_is_the_platform_audit_slug() {
            assert_eq!(PLATFORM_AUDIT_ROUTE_KEY, "audit");
            assert_eq!(PLATFORM_AUDIT_ROUTE_KEY, platform_audit_lane::AUDIT_SLUG);
        }

        /// A landed audit row is the row a Vector tenant writes for the same
        /// delivered line: the base's audit lane, then its storage stage.
        #[test]
        fn a_landed_audit_row_is_the_row_vector_writes() {
            let stage = LandingOcsfStage::new(1).unwrap();
            let landed = stage.prepare(audit_event(AUDIT_TENANT), &audit_ctx()).unwrap();
            let landed_event = event_of(&landed);
            let base = archive::unpack(include_bytes!("tenant_bundle/testdata/platform-base-zero.tar.gz")).unwrap();
            let with = platform_audit_lane::add_platform_audit_lane(&base).unwrap();
            let line = serde_json::to_string(&audit_event(AUDIT_TENANT)).unwrap();
            let mut vector = platform_audit_lane::lake_row(&with, &line, AUDIT_TENANT).unwrap();
            // Vector's sink strips these two before writing the bronze event.
            let vector = vector.as_object_mut().map(|row| {
                row.remove("_nano_bronze_partition");
                row.remove("time");
                Value::Object(row.clone())
            }).unwrap();
            assert_eq!(comparable(landed_event.clone()), comparable(vector));
            assert_eq!(landed_event["metadata"]["log_source"], "audit");
            assert_eq!(landed_event["metadata"]["tenant_uid"], AUDIT_TENANT);
            assert_eq!(landed_event["metadata"]["uid"], EVENT_ID, "the audit id stays the uid: replays dedupe");
            assert_eq!(landed_event["metadata"]["ingress_transport"], LANDING_INGRESS_TRANSPORT);
            // NAN-3304 anchors: a null-only endpoint and actor become the emitting service.
            assert_eq!(landed_event["src_endpoint"]["svc_name"], "identity");
            assert_eq!(landed_event["actor"], json!({"app_name": "identity"}));
            let unmapped: Value = serde_json::from_str(landed_event["unmapped"].as_str().unwrap()).unwrap();
            assert_eq!(unmapped["nano_src_endpoint"], "synthesized:emitting_service");
            assert_eq!(landed.uid, EVENT_ID);
        }

        /// The lane's guard holds on the landing path too: nothing that is not
        /// this tenant's nano platform audit event lands as `log_source = audit`.
        #[test]
        fn the_audit_lane_guard_refuses_foreign_or_non_audit_rows() {
            let stage = LandingOcsfStage::new(1).unwrap();
            assert_eq!(stage.prepare(audit_event(OTHER_TENANT), &audit_ctx()).unwrap_err(), StageError::Aborted);
            let mut not_nano = audit_event(AUDIT_TENANT);
            not_nano["metadata"]["product"]["name"] = json!("acme");
            assert_eq!(stage.prepare(not_nano, &audit_ctx()).unwrap_err(), StageError::Aborted);
            // A sender's sysmon row cannot ride the audit source either.
            assert_eq!(stage.prepare(sysmon(Some("u")), &audit_ctx()).unwrap_err(), StageError::Aborted);
        }

        /// Every other route key is untouched: the lane runs only for `audit`.
        #[test]
        fn other_route_keys_skip_the_audit_lane() {
            let stage = LandingOcsfStage::new(1).unwrap();
            let mut ctx = audit_ctx();
            ctx.source_type = "tenzir_audit";
            let row = stage.prepare(audit_event(AUDIT_TENANT), &ctx).unwrap();
            let event = event_of(&row);
            assert_eq!(event["metadata"]["log_source"], "tenzir_audit");
            assert!(event["src_endpoint"].get("svc_name").is_none(), "no lane anchoring outside `audit`");
        }

        /// The retained-clock factory (native durable retries) compiles the lane too.
        #[test]
        fn the_fixed_clock_stage_runs_the_lane() {
            let received = DateTime::<Utc>::from_timestamp_millis(1_792_843_200_123).unwrap();
            let stage = LandingOcsfStage::new_at(1, received).unwrap();
            let row = stage.prepare(audit_event(AUDIT_TENANT), &audit_ctx()).unwrap();
            assert_eq!(event_of(&row)["metadata"]["log_source"], "audit");
        }
    }
}
