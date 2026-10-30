// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded tenant-private ingest receipts. Ordinary traffic creates no receipts.
//! An Add's published signed parts are searchable once its log entry commits.
//! Pod replacement loses this short-lived index and fails closed: verification
//! must issue fresh probes. No lake query, time inference or R2 operation here.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

pub const TTL_MS: i64 = 2 * 3_600_000;
pub const MAX_RECEIPTS: usize = 4096;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub nonce: Uuid,
    pub source: String,
    pub bundle: String,
    pub event_time: Value,
    pub ingest_time_ms: i64,
    pub parse_error: bool,
    pub platform: bool,
    pub committed: bool,
    pub searchable: bool,
    pub log_seq: u64,
    pub log_sha256: String,
}
#[derive(Clone)]
pub struct Receipts {
    tenant: String,
    rows: Arc<RwLock<BTreeMap<Uuid, Receipt>>>,
}
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Lookup {
    pub request_id: Uuid,
    pub tenant_id: String,
    pub source: String,
    pub bundle: String,
    pub probe_nonce: Uuid,
    #[serde(default)]
    pub platform_probe_id: Option<Uuid>,
}
impl Lookup {
    pub fn valid(&self) -> bool {
        !self.request_id.is_nil()
            && !self.probe_nonce.is_nil()
            && !self.source.is_empty()
            && self.source.len() <= 100
            && self
                .source
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
            && self.bundle.len() == 64
            && self
                .bundle
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.platform_probe_id.is_none_or(|id| {
                id == self.probe_nonce
                    && ["audit", "otlp_log", "unknown"].contains(&self.source.as_str())
            })
    }
}
impl Receipts {
    pub fn new(tenant: &str) -> Self {
        Self {
            tenant: tenant.into(),
            rows: Default::default(),
        }
    }
    pub fn commit(&self, receipts: Vec<Receipt>, seq: u64, sha256: &str, now_ms: i64) {
        if receipts.is_empty() {
            return;
        }
        let mut rows = self.rows.write().expect("landing receipts");
        rows.retain(|_, row| row.ingest_time_ms <= now_ms && row.ingest_time_ms + TTL_MS > now_ms);
        for mut row in receipts {
            if rows.len() >= MAX_RECEIPTS && !rows.contains_key(&row.nonce) {
                continue;
            }
            row.committed = true;
            row.searchable = true;
            row.log_seq = seq;
            row.log_sha256 = sha256.into();
            match rows.entry(row.nonce) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(row);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let first = entry.get_mut();
                    // Every row of a multiline sample shares its nonce. Any
                    // parse failure is sticky; ambiguous scope never passes.
                    first.parse_error |= row.parse_error;
                    first.searchable &= first.source == row.source
                        && first.bundle == row.bundle
                        && first.platform == row.platform;
                }
            }
        }
    }
    pub fn lookup(&self, request: &Lookup, now_ms: i64) -> Result<Value> {
        anyhow::ensure!(
            request.valid() && request.tenant_id == self.tenant,
            "landing_receipt_scope_invalid"
        );
        let rows = self.rows.read().expect("landing receipts");
        let receipt = rows.get(&request.probe_nonce).filter(|r| {
            r.source == request.source
                && r.bundle == request.bundle
                && r.ingest_time_ms <= now_ms
                && r.ingest_time_ms + TTL_MS > now_ms
                && r.committed
                && r.searchable
                && (request.platform_probe_id.is_none() || r.platform)
        });
        Ok(
            json!({"ok":true,"route":"landing_receipt_v1","request_id":request.request_id,
            "tenant_id":self.tenant,"probe_nonce":request.probe_nonce,"source":request.source,"bundle":request.bundle,
            "receipt":receipt, "estimated_scan_bytes":0}),
        )
    }
}
/// Inspect explicit nonce fields and parser-preserved raw samples only.
/// Platform probes must already have passed the production signature guard.
pub fn recognize(event: &Value, now_ms: i64) -> Option<Receipt> {
    let platform = event
        .pointer("/unmapped/nano_platform_probe_trusted")
        .and_then(Value::as_str)
        == Some("v1");
    let nonce = if platform {
        event
            .pointer("/unmapped/nano_platform_probe_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
    } else {
        let raw = event.get("raw_data").and_then(Value::as_str)?;
        if !raw.contains("nano_probe") {
            return None;
        }
        let found = raw
            .split_once("nano_probe=")
            .and_then(|(_, s)| s.get(..36))
            .and_then(|s| Uuid::parse_str(s).ok());
        fn json_nonce(value: &Value, depth: usize) -> Option<Uuid> {
            if depth > 4 {
                return None;
            }
            if let Some(n) = value
                .get("nano_probe_nonce")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
            {
                return Some(n);
            }
            for key in ["message", "log", "ocsf_event"] {
                if let Some(v) = value.get(key) {
                    if let Some(n) = v
                        .as_str()
                        .and_then(|s| serde_json::from_str::<Value>(s).ok())
                        .and_then(|v| json_nonce(&v, depth + 1))
                        .or_else(|| json_nonce(v, depth + 1))
                    {
                        return Some(n);
                    }
                }
            }
            None
        }
        found.or_else(|| {
            serde_json::from_str::<Value>(raw)
                .ok()
                .and_then(|v| json_nonce(&v, 0))
        })
    }?;
    if nonce.is_nil() {
        return None;
    }
    let source = event.pointer("/metadata/log_source")?.as_str()?;
    let bundle = event
        .pointer("/metadata/nano_parser_bundle_sha256")?
        .as_str()?;
    if source.is_empty()
        || source.len() > 100
        || !source
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        || bundle.len() != 64
        || !bundle
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    Some(Receipt {
        nonce,
        source: source.into(),
        bundle: bundle.into(),
        event_time: event.get("time").cloned().unwrap_or(Value::Null),
        ingest_time_ms: now_ms,
        parse_error: event
            .pointer("/unmapped/parse_error")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty()),
        platform,
        committed: false,
        searchable: false,
        log_seq: 0,
        log_sha256: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_ttl_parse_errors_and_platform_identity_fail_closed() {
        let receipts = Receipts::new("tenant");
        let nonce = Uuid::new_v4();
        let now = 1800000000000;
        let event = json!({"time":1,"raw_data":format!("<134>probe nano_probe={nonce}"),"metadata":{"log_source":"audit","nano_parser_bundle_sha256":"a".repeat(64)},"unmapped":{"parse_error":"invalid"}});
        let row = recognize(&event, now).unwrap();
        assert!(row.parse_error);
        assert!(!row.committed);
        let mut lookup = Lookup {
            request_id: Uuid::new_v4(),
            tenant_id: "tenant".into(),
            source: "audit".into(),
            bundle: "a".repeat(64),
            probe_nonce: nonce,
            platform_probe_id: Some(nonce),
        };
        let mut ok_row = row.clone();
        ok_row.parse_error = false;
        receipts.commit(vec![row.clone(), ok_row], 2, &"b".repeat(64), now);
        assert!(
            receipts.lookup(&lookup, now).unwrap()["receipt"].is_null(),
            "sample nonce is not a signed platform identity"
        );
        lookup.platform_probe_id = None;
        assert_eq!(
            receipts.lookup(&lookup, now).unwrap()["receipt"]["parse_error"],
            true
        );
        assert!(receipts.lookup(&lookup, now + TTL_MS).unwrap()["receipt"].is_null());
        let rows = (0..MAX_RECEIPTS + 1)
            .map(|i| Receipt {
                nonce: Uuid::from_u128(i as u128 + 1),
                ..row.clone()
            })
            .collect();
        receipts.commit(rows, 3, &"c".repeat(64), now + TTL_MS);
        assert_eq!(receipts.rows.read().unwrap().len(), MAX_RECEIPTS);
        let mut ordinary = event;
        ordinary["raw_data"] = json!("ordinary log line");
        assert!(recognize(&ordinary, now).is_none());
        lookup.tenant_id = "other".into();
        assert!(receipts.lookup(&lookup, now).is_err());
    }
}
