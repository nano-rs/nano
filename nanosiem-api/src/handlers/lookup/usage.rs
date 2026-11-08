// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup table usage handler — lists detection rules referencing a given table.
//!
//! Powers the **Usage** section of the redesigned LookupTableView Details
//! inspector (NAN-509 / NAN-510 / NAN-511).

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use tracing::instrument;

use nanosiem_core::auth::permissions;
use nanosiem_core::{LookupUsage, RuleReferenceRow};

use super::lookup_error_to_api;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Maximum sample-join length, in characters, before we truncate.
const MAX_SAMPLE_JOIN_LEN: usize = 200;

/// List detection rules referencing a lookup table
///
/// `GET /api/lookup-tables/{name}/usage`
///
/// Returns the detection rules whose nPL `query` body contains a `@<name>`
/// reference to this lookup. Used by the LookupTableView **Usage** panel to
/// show analysts which detections depend on the table before they edit or
/// delete it.
///
/// # Stub fields
///
/// `hits_24h` and `last_hit` are currently stubbed to `0` and `null`
/// respectively. Wiring up per-rule signal counts from the ClickHouse
/// `signals` table is deferred — see `TODO(NAN-511)` in
/// [`LookupUsage`](nanosiem_core::LookupUsage).
#[utoipa::path(
    get,
    path = "/api/lookup-tables/{name}/usage",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name")
    ),
    responses(
        (status = 200, description = "Rules referencing the lookup table", body = Vec<LookupUsage>),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Lookup table not found"),
    ),
    security(("api_key" = []))
)]
#[instrument(skip(state, auth))]
pub async fn get_lookup_table_usage(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(name): Path<String>,
) -> Result<Json<Vec<LookupUsage>>, ApiError> {
    // Composite operation: the response domain is lookup management, but the
    // handler reads protected detection content (rule IDs, names, tactics, and
    // up to 200 chars of the rule's nPL query via `sample_join`). Require
    // `detections:view` in addition to `lookup:view` so a lookup-only caller
    // that GET /api/rules/{id} correctly denies cannot recover the same detection
    // metadata here (NAN-2105 / CWE-862).
    ensure_permission(&auth, permissions::LOOKUP_VIEW)?;
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let lookup_service = state.lookup_service.clone();

    // 404 if the table doesn't exist — this preserves the contract "the
    // endpoint is scoped to a real table" and matches GET /:name behavior.
    let _table = lookup_service
        .get_table(&name)
        .await
        .map_err(lookup_error_to_api)?;

    let rule_refs = lookup_service
        .find_rules_referencing(&name)
        .await
        .map_err(lookup_error_to_api)?;

    let token = format!("@{}", name);
    let usage: Vec<LookupUsage> = rule_refs
        .into_iter()
        .map(|r| build_usage(r, &token))
        .collect();

    Ok(Json(usage))
}

/// Convert a [`RuleReferenceRow`] into a public [`LookupUsage`] payload.
///
/// Picks the first MITRE tactic (if any) and extracts a sample join clause.
fn build_usage(r: RuleReferenceRow, token: &str) -> LookupUsage {
    let tactic = r.mitre_tactics.first().cloned();
    let sample_join = extract_sample_join(&r.query, token);
    LookupUsage {
        rule_id: r.id,
        rule_name: r.name,
        tactic,
        // TODO(NAN-511): pull from ClickHouse signals table.
        hits_24h: 0,
        last_hit: None,
        sample_join,
    }
}

/// Extract a sample-join clause from a rule's nPL `query` body.
///
/// Strategy:
/// 1. Find the first line containing `token` (case-insensitive). If found and
///    the line is short enough, return it trimmed.
/// 2. Otherwise, return a window centered on the token (up to
///    [`MAX_SAMPLE_JOIN_LEN`] chars), with leading/trailing ellipses if it
///    was clipped.
/// 3. If `token` is somehow not present (defensive), fall back to the whole
///    query truncated to [`MAX_SAMPLE_JOIN_LEN`].
fn extract_sample_join(query: &str, token: &str) -> String {
    let query_lc = query.to_lowercase();
    let token_lc = token.to_lowercase();

    let token_pos = query_lc.find(&token_lc);

    // Walk lines and pick the first one containing the token (case-insensitive).
    for line in query.lines() {
        if line.to_lowercase().contains(&token_lc) {
            let trimmed = line.trim();
            if !trimmed.is_empty() && trimmed.len() <= MAX_SAMPLE_JOIN_LEN {
                return trimmed.to_string();
            }
            // Long line — fall through to the windowed extractor below.
            break;
        }
    }

    // Windowed extraction around the token, if we found one.
    if let Some(pos) = token_pos {
        return windowed(query, pos, token.len(), MAX_SAMPLE_JOIN_LEN);
    }

    // Defensive fallback (token not present at all — shouldn't happen since
    // the SQL pre-filtered on this token).
    truncate(query.trim(), MAX_SAMPLE_JOIN_LEN)
}

/// Return a substring of `s` of at most `max_len` chars centered on the
/// `[start, start+token_len)` slice, with ellipses where clipped. Splits on
/// whitespace where possible to avoid mid-word breaks.
fn windowed(s: &str, start: usize, token_len: usize, max_len: usize) -> String {
    let bytes = s.as_bytes();
    let total = bytes.len();
    if total <= max_len {
        return s.trim().to_string();
    }
    let token_end = start + token_len;
    // Aim to put roughly equal context on each side.
    let context = max_len.saturating_sub(token_len) / 2;
    let mut left = start.saturating_sub(context);
    let mut right = token_end.saturating_add(context).min(total);

    // Snap left forward to a char boundary + whitespace if we can.
    while left > 0 && !s.is_char_boundary(left) {
        left -= 1;
    }
    while right < total && !s.is_char_boundary(right) {
        right += 1;
    }
    if left > 0 {
        if let Some(ws) = s[left..token_end].find(char::is_whitespace) {
            left += ws + 1;
        }
    }
    if right < total {
        if let Some(ws) = s[token_end..right].rfind(char::is_whitespace) {
            right = token_end + ws;
        }
    }

    let mut out = String::new();
    if left > 0 {
        out.push_str("…");
    }
    out.push_str(s[left..right].trim());
    if right < total {
        out.push_str("…");
    }
    out
}

/// Hard-truncate to `max_len` characters (char-boundary aware), appending an
/// ellipsis if clipped.
fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_len.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_sample_join_picks_short_line() {
        let q = "src_ip != \"0.0.0.0\"\n| where dest_ip IN @malicious_ips.ip\n| stats count by src_ip";
        let s = extract_sample_join(q, "@malicious_ips");
        assert_eq!(s, "| where dest_ip IN @malicious_ips.ip");
    }

    #[test]
    fn extract_sample_join_windows_long_single_line() {
        let prefix = "x".repeat(300);
        let suffix = "y".repeat(300);
        let q = format!("{} dest_ip IN @malicious_ips.ip {}", prefix, suffix);
        let s = extract_sample_join(&q, "@malicious_ips");
        assert!(
            s.chars().count() <= MAX_SAMPLE_JOIN_LEN + 2, // +2 for ellipses
            "windowed sample-join should be roughly capped, got len={}",
            s.chars().count()
        );
        assert!(
            s.contains("@malicious_ips"),
            "windowed sample-join must contain the token: {}",
            s
        );
    }

    #[test]
    fn extract_sample_join_handles_case_insensitive_match() {
        let q = "WHERE x = @MaliciousIPs.ip";
        let s = extract_sample_join(q, "@maliciousips");
        assert_eq!(s, "WHERE x = @MaliciousIPs.ip");
    }

    #[test]
    fn truncate_respects_char_boundary() {
        let s = "abcdefghij";
        assert_eq!(truncate(s, 5), "abcd…");
        assert_eq!(truncate(s, 100), "abcdefghij");
    }
}
