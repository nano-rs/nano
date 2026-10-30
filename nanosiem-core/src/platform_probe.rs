// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signed, closed platform probe envelopes. Only ingestion may set the trusted
//! exclusion stamp. An envelope can represent only the fixed inert event below.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

pub const TRUSTED_FIELD: &str = "nano_platform_probe_trusted";
pub const PROBE_ID_FIELD: &str = "nano_platform_probe_id";
pub const DOMAIN: &[u8] = b"nano.platform-probe.v1\0";
pub const SOURCES: &[&str] = &["unknown", "otlp_log", "audit"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlatformProbeKey {
    pub tenant_id: Uuid,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlatformProbe {
    pub tenant_id: Uuid,
    pub roll_id: Uuid,
    pub probe_id: Uuid,
    pub source_slug: String,
    pub parser_bundle_sha256: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    #[serde(default)]
    pub signature_hex: String,
}
impl PlatformProbe {
    fn message(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.signature_hex.clear();
        [
            DOMAIN,
            serde_json::to_vec(&unsigned)
                .expect("closed probe schema")
                .as_slice(),
        ]
        .concat()
    }
    pub fn sign(&mut self, key: &SigningKey) {
        self.signature_hex = hex::encode(key.sign(&self.message()).to_bytes());
    }
    pub fn verify(&self, key: &PlatformProbeKey, tenant: Uuid, source: &str, now_ms: i64) -> bool {
        if key.public_key_hex.len() != 64 || self.signature_hex.len() != 128 {
            return false;
        }
        let Some(public) = hex::decode(&key.public_key_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return false;
        };
        let Ok(public) = VerifyingKey::from_bytes(&public) else {
            return false;
        };
        let Some(signature) = hex::decode(&self.signature_hex)
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
        else {
            return false;
        };
        key.tenant_id == tenant
            && self.tenant_id == tenant
            && !tenant.is_nil()
            && !self.roll_id.is_nil()
            && !self.probe_id.is_nil()
            && SOURCES.contains(&source)
            && self.source_slug == source
            && self.parser_bundle_sha256.len() == 64
            && self
                .parser_bundle_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            && self.issued_at_ms >= 0
            && self.issued_at_ms <= now_ms.saturating_add(60_000)
            && now_ms < self.expires_at_ms
            && self
                .expires_at_ms
                .checked_sub(self.issued_at_ms)
                .is_some_and(|ttl| (1..=900_000).contains(&ttl))
            && public.verify_strict(&self.message(), &signature).is_ok()
    }
    /// Valid OCSF API Activity, admitted by the existing audit lane too.
    pub fn event(&self) -> Value {
        let raw = serde_json::to_string(self).expect("closed probe schema");
        json!({"class_uid":6003,"category_uid":6,"activity_id":1,"type_uid":600301,
            "severity_id":1,"status_id":1,"time":self.issued_at_ms,
            "message":"nano Security Lake runtime landing probe", "raw_data":raw, "raw_data_size":raw.len(),
            "metadata":{"uid":self.probe_id,"tenant_uid":self.tenant_id,"version":"1.9.0",
                "nano_parser_bundle_sha256":self.parser_bundle_sha256,
                "log_name":"audit","log_source":self.source_slug,"product":{"name":"nano","vendor_name":"nano"}},
            "actor":{"app_name":"nano runtime landing probe"},"api":{"operation":"runtime_landing_probe","service":{"name":"nano"}},
            "src_endpoint":{"name":"nano runtime landing probe"},
            "unmapped":{"nano_platform_probe":serde_json::to_string(self).expect("closed probe schema")}})
    }
}

/// Always strip caller stamps. Verify the sealed payload, then reconstruct its
/// entire inert event: unsigned extra actor/process/risk fields cannot hitchhike
/// on a genuine signature. Existing parser bundle metadata stays attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeAdmission {
    Ordinary,
    Verified,
    Refused,
}

pub fn admit(event: &mut Value, key: Option<&PlatformProbeKey>, tenant: &str, now_ms: i64) -> bool {
    inspect(event, key, tenant, now_ms) == ProbeAdmission::Verified
}

pub fn inspect(
    event: &mut Value,
    key: Option<&PlatformProbeKey>,
    tenant: &str,
    now_ms: i64,
) -> ProbeAdmission {
    if let Some(unmapped) = event.get_mut("unmapped").and_then(Value::as_object_mut) {
        unmapped.remove(TRUSTED_FIELD);
        unmapped.remove(PROBE_ID_FIELD);
    }
    // The common ingest path does not parse raw JSON or perform cryptography.
    if event.pointer("/unmapped/nano_platform_probe").is_none()
        && !event
            .get("raw_data")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("nano_platform_probe"))
    {
        return ProbeAdmission::Ordinary;
    }
    let Some(probe) = closed_probe(event) else {
        return if has_probe_envelope(event) {
            ProbeAdmission::Refused
        } else {
            ProbeAdmission::Ordinary
        };
    };
    let Some(key) = key else {
        return ProbeAdmission::Refused;
    };
    let Ok(tenant) = Uuid::parse_str(tenant) else {
        return ProbeAdmission::Refused;
    };
    let Some(source) = event
        .pointer("/metadata/log_source")
        .and_then(Value::as_str)
    else {
        return ProbeAdmission::Refused;
    };
    if !probe.verify(key, tenant, source, now_ms)
        || event
            .pointer("/metadata/nano_parser_bundle_sha256")
            .and_then(Value::as_str)
            != Some(&probe.parser_bundle_sha256)
    {
        return ProbeAdmission::Refused;
    }
    let ingress = [
        "processed_time",
        "logged_time",
        "nano_credential_id",
        "ingress_transport",
    ]
    .into_iter()
    .filter_map(|key| {
        event["metadata"]
            .get(key)
            .cloned()
            .map(|value| (key, value))
    })
    .collect::<Vec<_>>();
    let normalized_time = event.get("time").cloned();
    let original_uid = event.pointer("/metadata/uid").cloned();
    *event = probe.event();
    if let Some(time) = normalized_time {
        event["time"] = time;
    }
    if let Some(uid) = original_uid {
        event["metadata"]["uid"] = uid;
    }
    for (key, value) in ingress {
        event["metadata"][key] = value;
    }
    event["unmapped"][TRUSTED_FIELD] = json!("v1");
    event["unmapped"][PROBE_ID_FIELD] = json!(probe.probe_id);
    ProbeAdmission::Verified
}

fn has_probe_envelope(event: &Value) -> bool {
    if event.pointer("/unmapped/nano_platform_probe").is_some() {
        return true;
    }
    let Some(raw) = event
        .get("raw_data")
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
    else {
        return false;
    };
    raw.pointer("/unmapped/nano_platform_probe").is_some()
        || raw
            .get("message")
            .and_then(Value::as_str)
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .is_some_and(|inner| inner.pointer("/unmapped/nano_platform_probe").is_some())
}

/// Recognize only the complete closed inert envelope. A marker attached to
/// arbitrary real telemetry is refused rather than acquiring an exemption.
fn closed_probe(event: &Value) -> Option<PlatformProbe> {
    let raw = event
        .get("raw_data")
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    let generic = raw
        .as_ref()
        .filter(|v| {
            v.as_object().is_some_and(|o| {
                o.keys().all(|k| {
                    ["message", "metadata", "source_type", "timestamp"].contains(&k.as_str())
                })
            })
        })
        .and_then(|v| v.get("message"))
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    let source_payload = generic.as_ref().or_else(|| {
        raw.as_ref()
            .filter(|v| v.pointer("/unmapped/nano_platform_probe").is_some())
    });
    let envelope = source_payload.unwrap_or(event);
    let probe = envelope
        .pointer("/unmapped/nano_platform_probe")
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str::<PlatformProbe>(s).ok())?;
    if generic.is_some() {
        let wrapper = raw.as_ref()?;
        let metadata = wrapper.get("metadata")?.as_object()?;
        if metadata
            .keys()
            .any(|key| !["parser_type", "original_source_type"].contains(&key.as_str()))
            || metadata.get("parser_type").and_then(Value::as_str) != Some("generic")
            || metadata.get("original_source_type").and_then(Value::as_str)
                != Some(&probe.source_slug)
            || wrapper
                .get("source_type")
                .and_then(Value::as_str)
                .is_some_and(|source| source != probe.source_slug)
        {
            return None;
        }
    }
    let mut actual = envelope.clone();
    if source_payload.is_none() {
        if let Some(metadata) = actual.get_mut("metadata").and_then(Value::as_object_mut) {
            for key in [
                "processed_time",
                "logged_time",
                "nano_credential_id",
                "ingress_transport",
            ] {
                metadata.remove(key);
            }
        }
        if let Some(time) = actual
            .get("time")
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        {
            actual["time"] = json!(time.timestamp_millis());
        }
    }
    (actual == probe.event()).then_some(probe)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (PlatformProbe, PlatformProbeKey) {
        let key = SigningKey::from_bytes(&[17; 32]);
        let mut p = PlatformProbe {
            tenant_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            roll_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
            probe_id: Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
            source_slug: "audit".into(),
            parser_bundle_sha256: "a".repeat(64),
            issued_at_ms: 1000,
            expires_at_ms: 901000,
            signature_hex: String::new(),
        };
        p.sign(&key);
        (
            p,
            PlatformProbeKey {
                tenant_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            },
        )
    }
    #[test]
    fn transport_probes_preserve_ingress_uid_and_cannot_hide_extra_metadata() {
        let (mut p, key) = fixture();
        for source in ["unknown", "otlp_log"] {
            p.source_slug = source.into();
            p.sign(&SigningKey::from_bytes(&[17; 32]));
            let sample = p.event();
            let wrapper = json!({"message":serde_json::to_string(&sample).unwrap(),"source_type":source,
                "metadata":{"parser_type":"generic","original_source_type":source}});
            let mut event = sample.clone();
            event["metadata"]["uid"] = json!("ingress-raw-hash");
            event["raw_data"] = json!(serde_json::to_string(&wrapper).unwrap());
            event["raw_data_size"] = json!(event["raw_data"].as_str().unwrap().len());
            let original = event.clone();
            assert_eq!(
                inspect(&mut event, Some(&key), &p.tenant_id.to_string(), 2000),
                ProbeAdmission::Verified
            );
            assert_eq!(event["metadata"]["uid"], "ingress-raw-hash");
            assert_eq!(event["unmapped"][PROBE_ID_FIELD], json!(p.probe_id));
            let mut injected = original;
            let mut wrapper = wrapper;
            wrapper["metadata"]["user"] = json!("real-activity");
            injected["raw_data"] = json!(serde_json::to_string(&wrapper).unwrap());
            assert_eq!(
                inspect(&mut injected, Some(&key), &p.tenant_id.to_string(), 2000),
                ProbeAdmission::Refused
            );
        }
    }

    #[test]
    fn platform_probe_cross_language_wire_vector() {
        use base64::Engine;
        let vector: Value =
            serde_json::from_str(include_str!("testdata/platform-probe-v1.json")).unwrap();
        let (probe, key) = fixture();
        assert_eq!(
            serde_json::to_value(&probe).unwrap(),
            vector["probe"]["platform_probe"]
        );
        assert_eq!(key.public_key_hex, vector["public_key_hex"]);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(vector["probe"]["delivery"]["body_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(bytes, serde_json::to_vec(&probe.event()).unwrap());
    }

    #[test]
    fn platform_probe_survives_the_production_audit_lane() {
        use crate::parsers::tenant_bundle::{archive, platform_audit_lane};
        let (probe, key) = fixture();
        let base = archive::unpack(include_bytes!(
            "parsers/tenant_bundle/testdata/platform-base-zero-collector-v2.tar.gz"
        ))
        .unwrap();
        let base = platform_audit_lane::add_platform_audit_lane(&base).unwrap();
        let row = platform_audit_lane::lake_row(
            &base,
            &serde_json::to_string(&probe.event()).unwrap(),
            &probe.tenant_id.to_string(),
        )
        .unwrap();
        let unmapped: Value = serde_json::from_str(row["unmapped"].as_str().unwrap()).unwrap();
        let sealed: PlatformProbe =
            serde_json::from_str(unmapped["nano_platform_probe"].as_str().unwrap()).unwrap();
        assert!(sealed.verify(&key, probe.tenant_id, "audit", 2000));
        assert_eq!(row["raw_data"], probe.event()["raw_data"]);
        assert_eq!(row["metadata"]["uid"], json!(probe.probe_id));
    }

    #[test]
    fn signed_probe_is_scoped_and_closed() {
        let (p, key) = fixture();
        let mut event = p.event();
        assert!(admit(
            &mut event,
            Some(&key),
            &p.tenant_id.to_string(),
            2000
        ));
        assert_eq!(event["unmapped"][TRUSTED_FIELD], "v1");
        assert_eq!(
            inspect(&mut p.event(), None, &p.tenant_id.to_string(), 2000),
            ProbeAdmission::Refused
        );
        for mode in [
            "tenant",
            "signature",
            "expired",
            "payload",
            "key",
            "source",
            "stamp",
            "metadata",
        ] {
            let mut p = p.clone();
            let mut k = key.clone();
            match mode {
                "tenant" => p.tenant_id = Uuid::from_u128(4),
                "signature" => p.signature_hex.clear(),
                "expired" => p.expires_at_ms = 1500,
                "key" => k.public_key_hex = "0".repeat(64),
                "source" => p.source_slug = "apache_access".into(),
                _ => (),
            }
            let mut e = p.event();
            if mode == "payload" {
                e["actor"]["app_name"] = json!("malicious");
            }
            if mode == "metadata" {
                e["metadata"]["user"] = json!("malicious");
            }
            e["unmapped"][TRUSTED_FIELD] = json!("v1");
            if mode == "stamp" {
                e["unmapped"]
                    .as_object_mut()
                    .unwrap()
                    .remove("nano_platform_probe");
            }
            assert!(
                !admit(&mut e, Some(&k), &key.tenant_id.to_string(), 2000),
                "{mode}"
            );
            assert!(e["unmapped"].get(TRUSTED_FIELD).is_none(), "{mode}");
        }
    }
}
