// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire contract of a risk read (NAN-3035).
//!
//! Two backends answer the same typed risk request: the gen1 reader
//! (`POST /v1/query`, `route: "risk"`) and the lean cell (`POST /v1/risk`).
//! Both return one flat envelope: the reader's `RiskService` output
//! (`snapshot`, `budget`, `result.rows`) with `ok`, `request_id`,
//! `tenant_id` and `route` merged into the top level; the cell adds
//! `source_mode: "parts"` and `log_seq`.
//!
//! The API (`enterprise::risk::lake`) parses with
//! [`RiskReadEnvelope`], and the lake worker's contract test parses the
//! cell's real response with the same type, so the two sides cannot drift
//! again (the cell once nested the reader envelope under `result`, which
//! surfaced as "missing field `rows`" on every lean tenant).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `source_mode` of a lean cell risk response.
pub const CELL_SOURCE_MODE: &str = "parts";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReadEnvelope<T> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<RiskSnapshotRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<RiskReadResult<T>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_seq: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSnapshotRef {
    pub tenant_id: String,
    pub snapshot_id: String,
    pub snapshot_version: String,
}

/// The rows of a risk read. An empty `rows` is a valid answer (no findings
/// in the horizon yet), never an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReadResult<T> {
    pub rows: Vec<T>,
}

impl<T> RiskReadEnvelope<T> {
    /// Accept a lean cell response for `tenant_id`: it must be `ok`, pinned
    /// to the tenant, served from the part log, and carry a result.
    pub fn into_cell_rows(self, tenant_id: &str) -> Result<Vec<T>, String> {
        if !self.ok {
            return Err(self
                .error
                .unwrap_or_else(|| "risk cell returned ok=false".to_string()));
        }
        if self.tenant_id.as_deref() != Some(tenant_id) {
            return Err("risk lake worker response tenant mismatch".to_string());
        }
        if self.source_mode.as_deref() != Some(CELL_SOURCE_MODE) {
            return Err("risk cell response omitted part-log source mode".to_string());
        }
        self.result
            .map(|result| result.rows)
            .ok_or_else(|| "risk cell omitted result".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TENANT: &str = "aaaaaaaa-0000-4000-8000-000000000000";

    fn cell(result: Value) -> Value {
        json!({"ok": true, "request_id": "r", "tenant_id": TENANT, "route": "risk",
               "source_mode": "parts", "log_seq": 5533, "result": result})
    }

    #[test]
    fn empty_rows_are_a_valid_cell_answer() {
        let envelope: RiskReadEnvelope<Value> =
            serde_json::from_value(cell(json!({"rows": [], "result_rows": 0}))).unwrap();
        assert!(envelope.into_cell_rows(TENANT).unwrap().is_empty());
    }

    #[test]
    fn the_nested_reader_envelope_is_rejected() {
        // The pre-NAN-3035 cell shape: rows one level too deep.
        let nested = cell(json!({"budget": {"route": "risk"}, "result": {"rows": []}}));
        let error = serde_json::from_value::<RiskReadEnvelope<Value>>(nested).unwrap_err();
        assert!(error.to_string().contains("missing field `rows`"), "{error}");
    }

    #[test]
    fn cell_acceptance_checks_tenant_and_source_mode() {
        let parse = |value: Value| serde_json::from_value::<RiskReadEnvelope<Value>>(value).unwrap();
        let mut foreign = cell(json!({"rows": []}));
        foreign["tenant_id"] = json!("other");
        assert!(parse(foreign).into_cell_rows(TENANT).unwrap_err().contains("tenant mismatch"));
        let mut gen1 = cell(json!({"rows": []}));
        gen1.as_object_mut().unwrap().remove("source_mode");
        assert!(parse(gen1).into_cell_rows(TENANT).unwrap_err().contains("source mode"));
        let failed = json!({"ok": false, "error": "boom", "tenant_id": TENANT});
        assert_eq!(parse(failed).into_cell_rows(TENANT).unwrap_err(), "boom");
    }
}
