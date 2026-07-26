// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-473 — `POST /api/playbooks/dry-resolve`
//!
//! Pure-pipe preview endpoint: take a raw playbook markdown document plus an
//! alert (either by id, or inline as a JSON payload) and return the doc with
//! every `{{...}}` token resolved against a freshly-built [`RunContext`]
//! snapshot. No `playbook_runs` row is written.
//!
//! Designed for the authoring wizard's Review phase — authors can sanity-
//! check that their tokens land against a real, recent alert before sending
//! the playbook for review.
//!
//! ## Request shape
//!
//! ```json
//! {
//!   "doc": "# Step\\n[ ] check {{event.src_ip}} for {{entity.user}}",
//!   "alert_id": "alert_01hz..."          // OR
//!   "sample_alert": { "matched_events": [...], "rule_id": "...", ... }
//! }
//! ```
//!
//! Exactly one of `alert_id` / `sample_alert` must be set; both missing is a
//! 400. When both are present `alert_id` wins (it's the authoritative path).
//!
//! ## Resolved shape
//!
//! Mirrors `GET /api/playbook-runs/{id}/resolved` enough that the FE can
//! reuse its rendering: `resolved_doc` is the templated text, `unresolved`
//! lists tokens whose namespace didn't bind, and `context_summary` reports
//! what context made it into the snapshot (entity counts, populated case
//! fields) so the UI can show "we resolved against alert X — N entities,
//! rule Y" without a second API call.
//!
//! ## NAN-474 — hardening
//!
//! * `doc` is capped at 256 KiB (`MAX_DRY_RESOLVE_DOC_BYTES`). Templating
//!   cost grows with `{{...}}` token count, so an unbounded `doc` becomes
//!   a CPU amplifier.
//! * Permission tightened from `playbooks:view` → `playbooks:manage`. This
//!   endpoint only exists for the authoring Review phase; the permission
//!   model in this codebase distinguishes read (VIEW) from write/edit
//!   (MANAGE), and every other authoring mutation uses MANAGE. View-only
//!   roles still see resolved docs through actual run records.
//! * `sample_alert` is now a typed `DryResolveSampleAlert` struct — serde
//!   rejects wrong-typed fields at deserialization, so malformed payloads
//!   return a clean 400 instead of reaching the runtime.
//! * Rate limited to 30 requests/minute per user (see
//!   `middleware::rate_limit::dry_resolve_rate_limit_middleware`).

use axum::{extract::State, Extension, Json};
use nanosiem_core::auth::permissions;
use nanosiem_core::entity_extraction::EntityExtractor;
use nanosiem_core::playbooks::runtime::{build_snapshot_from_alert, resolve_string, RunContext};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use uuid::Uuid;

use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Max size of the `doc` field. Beyond this we return 413 — templating cost
/// is proportional to `{{...}}` token count, and an unbounded doc against
/// an expensive resolution context could be used as a CPU amplifier.
const MAX_DRY_RESOLVE_DOC_BYTES: usize = 256 * 1024;

/// Inline alert payload accepted by the dry-resolve endpoint.
///
/// Deliberately minimal — only the fields that feed template resolution are
/// surfaced. `matched_events` stays `Vec<JsonValue>` because the parser
/// contract upstream is heterogeneous JSON (UDM + `ext`), but the top-level
/// shape is enforced so malformed payloads (strings, numbers, wrong-typed
/// fields) deserialize-fail into a clean 400.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DryResolveSampleAlert {
    /// Optional alert id for display only — not used to look anything up.
    #[serde(default)]
    pub id: Option<String>,
    /// Rule id backing the alert — populates `{{rule.id}}` when present.
    #[serde(default)]
    pub rule_id: Option<String>,
    /// Rule name — populates `{{rule.name}}`.
    #[serde(default)]
    pub rule_name: Option<String>,
    /// Alert severity — populates `{{alert.severity}}`.
    #[serde(default)]
    pub severity: Option<String>,
    /// Heterogeneous matched event payloads. Events themselves are UDM-
    /// shaped JSON, so we don't force a schema on the individual entries —
    /// only that the wrapper is an array.
    #[serde(default)]
    pub matched_events: Vec<JsonValue>,
}

/// Request body for the dry-resolve endpoint.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct DryResolveRequest {
    /// Raw playbook markdown — the doc-as-authored, before save.
    pub doc: String,
    /// Resolve against an alert that already lives in Postgres.
    /// Format: TypeID (e.g. `alert_01hz...`) or bare UUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_id: Option<String>,
    /// OR resolve against an inline alert payload — useful when the author
    /// wants to test against a synthetic event before any real alert exists.
    /// NAN-474: typed struct (was `serde_json::Value`) so wrong-typed fields
    /// return a clean 400 instead of silently degrading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_alert: Option<DryResolveSampleAlert>,
}

/// Response body for the dry-resolve endpoint.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DryResolveResponse {
    /// The doc with every `{{...}}` token substituted.
    pub resolved_doc: String,
    /// Paths whose namespace was unknown — surfaced to the UI as a
    /// "missing context" indicator. Mirrors the `unresolved` field on the
    /// run-resolved endpoint.
    pub unresolved: Vec<String>,
    /// Snapshot summary the UI can render alongside the resolved doc:
    /// `{ alert_id, rule_id, rule_name, source_type, entity_counts }`.
    /// Shape isn't versioned — treat as freeform display metadata.
    pub context_summary: JsonValue,
}

/// Dry-resolve a playbook draft against an alert. No DB writes — pure pipe.
#[utoipa::path(
    post,
    path = "/api/playbooks/dry-resolve",
    tag = "playbooks",
    request_body = DryResolveRequest,
    responses(
        (status = 200, description = "Resolved doc + unresolved tokens + context summary",
            body = DryResolveResponse),
        (status = 400, description = "Missing both alert_id and sample_alert, or alert_id was malformed",
            body = crate::error::ErrorResponse),
        (status = 403, description = "Forbidden — missing playbooks:manage (or alerts:view when resolving by alert_id)"),
        (status = 404, description = "alert_id not found", body = crate::error::ErrorResponse),
        (status = 413, description = "`doc` exceeds the 256 KiB size limit",
            body = crate::error::ErrorResponse),
        (status = 429, description = "Rate limit exceeded (30 dry-resolves/minute per user)"),
    ),
    security(("api_key" = []))
)]
pub async fn dry_resolve(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<DryResolveRequest>,
) -> Result<Json<DryResolveResponse>, ApiError> {
    // NAN-474: dry-resolve is an authoring-wizard surface, not a read
    // affordance. Gate on MANAGE, consistent with the rest of the playbook
    // authoring API.
    ensure_permission(&auth, permissions::PLAYBOOKS_MANAGE)?;

    // NAN-474: doc size cap. The request body is already deserialized here,
    // so a transport-layer DefaultBodyLimit would still admit a small body —
    // this check lets the 413 error name the `doc` field specifically.
    if req.doc.len() > MAX_DRY_RESOLVE_DOC_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "`doc` is {} bytes; limit is {} bytes",
            req.doc.len(),
            MAX_DRY_RESOLVE_DOC_BYTES
        )));
    }

    // Validation: must have at least one source of context.
    if req.alert_id.is_none() && req.sample_alert.is_none() {
        return Err(ApiError::BadRequest(
            "One of `alert_id` or `sample_alert` is required.".to_string(),
        ));
    }

    let ctx_json = if let Some(alert_id_str) = req.alert_id.as_deref() {
        // NAN-2045: this path loads a persisted alert's matched events (log data) —
        // a cross-resource read that `playbooks:manage` does not authorize. Require
        // `alerts:view` too, matching the alerts read surface. Source scope below is
        // a secondary row filter, not the capability gate. (The inline
        // `sample_alert` path reads no persisted alert, so it needs no alerts:view.)
        ensure_permission(&auth, permissions::ALERTS_VIEW)?;

        // Authoritative path — load the real alert from Postgres and build
        // the snapshot the same way the rule-fire path does.
        let alert_uuid = parse_alert_id(alert_id_str)?;
        // NAN-1800: VIEWER scope, not unrestricted — a playbook author must
        // not use dry-resolve to read matched events of an alert derived from
        // sources denied to them (per-source RBAC + the audit gate). Mirrors
        // the handlers/alerts.rs composition.
        let scope = {
            let mut deny = auth.denied_sources.deny_set().clone();
            if !auth.has_permission(permissions::AUDIT_VIEW) {
                deny.insert("audit".to_string());
            }
            nanosiem_core::auth::ScopeSet::from_denied(deny)
        };
        let alert = state
            .detection_service
            .get_alert(alert_uuid, scope.deny_set())
            .await?;
        let entities = EntityExtractor::new().extract_from_events(&alert.matched_events);

        let sev_str = severity_str(&alert.severity);
        let alert_tid = nanosiem_core::typeid::encode("alert", &alert.id);
        // rule_id is None when the source rule was deleted (NAN-1356); the
        // snapshot tolerates an empty rule tid like it does a missing case.
        let rule_tid = alert
            .rule_id
            .map(|r| nanosiem_core::typeid::encode("rule", &r))
            .unwrap_or_default();

        // No case context in dry-resolve (this is pre-attach by definition).
        // The runtime tolerates a missing case block — `{{case.*}}` tokens
        // just resolve to empty.
        build_snapshot_from_alert(
            "",                       // case_id — absent during dry-resolve
            None,                     // case_title
            None,                     // case_severity
            &alert_tid,
            sev_str.as_deref(),
            Some(&rule_tid),
            alert.rule_name.as_deref(),
            sev_str.as_deref(),
            &alert.matched_events,
            &entities,
        )
    } else {
        // Inline-payload path — synthesise a snapshot from whatever the
        // caller handed us. Missing fields degrade to empty resolutions.
        let sample = req.sample_alert.as_ref().expect("validated above");
        snapshot_from_inline_payload(sample)
    };

    let ctx: RunContext = serde_json::from_value(ctx_json.clone()).unwrap_or_default();
    let resolution = resolve_string(&req.doc, &ctx);

    // De-dup unresolved paths so a token referenced 5× doesn't show up 5×.
    let mut unresolved = resolution.unresolved;
    unresolved.sort();
    unresolved.dedup();

    Ok(Json(DryResolveResponse {
        resolved_doc: resolution.out,
        unresolved,
        context_summary: build_context_summary(&ctx, &ctx_json),
    }))
}

/// Accept either a TypeID (`alert_01hz...`) or a bare UUID — the FE picker
/// hands us TypeIDs, but tests + curl callers find UUIDs handier.
fn parse_alert_id(s: &str) -> Result<Uuid, ApiError> {
    if let Ok(u) = Uuid::parse_str(s) {
        return Ok(u);
    }
    nanosiem_core::typeid::decode("alert", s)
        .map_err(|e| ApiError::BadRequest(format!("Invalid alert id `{}`: {}", s, e)))
}

/// `serde_json::to_value(Severity)` produces a string — peel it off into an
/// owned String for the snapshot builder, returning None on failure.
fn severity_str(sev: &nanosiem_core::Severity) -> Option<String> {
    serde_json::to_value(sev)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
}

/// Build a snapshot from a typed inline alert payload. The wrapper shape is
/// now enforced by serde; individual matched events stay heterogeneous.
fn snapshot_from_inline_payload(payload: &DryResolveSampleAlert) -> JsonValue {
    let matched_events = JsonValue::Array(payload.matched_events.clone());
    let entities = EntityExtractor::new().extract_from_events(&matched_events);

    build_snapshot_from_alert(
        "",
        None,
        None,
        payload.id.as_deref().unwrap_or(""),
        payload.severity.as_deref(),
        payload.rule_id.as_deref(),
        payload.rule_name.as_deref(),
        payload.severity.as_deref(),
        &matched_events,
        &entities,
    )
}

/// Compose the freeform `context_summary` JSON the UI renders alongside the
/// resolved doc. Pulls a few "good to know" facts off the snapshot —
/// stringly-keyed entity counts, alert + rule ids, and the `source_type`
/// inferred from the top matched event.
fn build_context_summary(ctx: &RunContext, ctx_json: &JsonValue) -> JsonValue {
    let entity_counts: serde_json::Map<String, JsonValue> = ctx
        .entities
        .iter()
        .map(|(k, v)| (k.clone(), JsonValue::from(v.len())))
        .collect();

    json!({
        "alert_id": ctx.alert.as_ref().map(|a| a.id.as_str()),
        "alert_severity": ctx.alert.as_ref().and_then(|a| a.severity.as_deref()),
        "rule_id": ctx.rule.as_ref().map(|r| r.id.as_str()),
        "rule_name": ctx.rule.as_ref().and_then(|r| r.name.as_deref()),
        "source_type": ctx.source_type.as_deref(),
        "has_top_matched_event": ctx.top_matched_event.is_some(),
        "entity_counts": JsonValue::Object(entity_counts),
        // Echo the full snapshot too so the FE can drill in for debugging
        // without a second roundtrip.
        "snapshot": ctx_json,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_alert_payload() -> DryResolveSampleAlert {
        DryResolveSampleAlert {
            id: Some("00000000-0000-0000-0000-000000000001".into()),
            rule_id: Some("00000000-0000-0000-0000-000000000002".into()),
            rule_name: Some("Root key use outside bastion".into()),
            severity: Some("high".into()),
            matched_events: vec![json!({
                "source_type": "cloudtrail",
                "user": "alice",
                "src_ip": "10.0.0.5",
                "process_name": "aws-cli",
            })],
        }
    }

    #[test]
    fn inline_payload_resolves_event_token_against_synthetic_alert() {
        let payload = synthetic_alert_payload();
        let snapshot = snapshot_from_inline_payload(&payload);
        let ctx: RunContext = serde_json::from_value(snapshot).unwrap();

        let r = resolve_string(
            "[ ] check {{event.src_ip}} for {{rule.name}}",
            &ctx,
        );
        assert!(
            r.out.contains("10.0.0.5"),
            "expected resolved doc to contain src_ip, got: {}",
            r.out
        );
        assert!(
            r.out.contains("Root key use outside bastion"),
            "expected resolved doc to contain rule.name, got: {}",
            r.out
        );
        assert!(r.unresolved.is_empty(), "expected no unresolved, got: {:?}", r.unresolved);
    }

    #[test]
    fn unknown_token_surfaces_in_unresolved() {
        let payload = synthetic_alert_payload();
        let snapshot = snapshot_from_inline_payload(&payload);
        let ctx: RunContext = serde_json::from_value(snapshot).unwrap();

        let r = resolve_string("[ ] grep {{widget.foo}}", &ctx);
        assert_eq!(r.unresolved, vec!["widget.foo".to_string()]);
        // Output keeps surrounding text, with the bad token rendered empty.
        assert_eq!(r.out, "[ ] grep ");
    }

    #[test]
    fn context_summary_includes_entity_counts_and_source_type() {
        let payload = synthetic_alert_payload();
        let snapshot = snapshot_from_inline_payload(&payload);
        let ctx: RunContext = serde_json::from_value(snapshot.clone()).unwrap();
        let summary = build_context_summary(&ctx, &snapshot);

        assert_eq!(summary["source_type"], "cloudtrail");
        assert_eq!(summary["has_top_matched_event"], true);
        assert!(
            summary["entity_counts"].is_object(),
            "entity_counts should be an object"
        );
        let counts = summary["entity_counts"].as_object().unwrap();
        assert!(
            counts.contains_key("ip") || counts.contains_key("src_ip"),
            "entity_counts should contain at least one IP-shaped bucket, got: {:?}",
            counts.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn parse_alert_id_accepts_bare_uuid() {
        let u = parse_alert_id("00000000-0000-0000-0000-000000000001").unwrap();
        let expected = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        assert_eq!(u, expected);
    }

    #[test]
    fn parse_alert_id_rejects_garbage() {
        let err = parse_alert_id("not-a-real-id").unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("Invalid alert id")),
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }

    // ---- NAN-474 hardening ----

    #[test]
    fn doc_size_cap_is_256_kib() {
        assert_eq!(MAX_DRY_RESOLVE_DOC_BYTES, 256 * 1024);
    }

    #[test]
    fn sample_alert_rejects_wrong_typed_severity() {
        // severity must be a string; a number should fail to deserialize
        // cleanly into 400 rather than reach the runtime.
        let bad = json!({ "severity": 7, "matched_events": [] });
        assert!(
            serde_json::from_value::<DryResolveSampleAlert>(bad).is_err(),
            "expected deserialization to fail when severity is not a string"
        );
    }

    #[test]
    fn sample_alert_rejects_matched_events_not_an_array() {
        let bad = json!({ "matched_events": "not-an-array" });
        assert!(
            serde_json::from_value::<DryResolveSampleAlert>(bad).is_err(),
            "expected deserialization to fail when matched_events is not an array"
        );
    }

    #[test]
    fn sample_alert_rejects_unknown_field() {
        // deny_unknown_fields means typos surface loudly rather than silently
        // no-op'ing — important for authors testing which tokens work.
        let bad = json!({ "matched_events": [], "severiity": "high" });
        assert!(
            serde_json::from_value::<DryResolveSampleAlert>(bad).is_err(),
            "expected deserialization to reject unknown field"
        );
    }

    #[test]
    fn sample_alert_accepts_minimal_empty_payload() {
        // Empty sample_alert is legitimate — resolutions just come back
        // unresolved. Deserialization must not fail on it.
        let ok = json!({});
        let parsed: DryResolveSampleAlert = serde_json::from_value(ok).unwrap();
        assert!(parsed.matched_events.is_empty());
    }
}
