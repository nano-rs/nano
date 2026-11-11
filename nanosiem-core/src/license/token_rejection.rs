// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5194: the license server rejected this deployment's token.
//!
//! A 401/403 from `/api/license/status` means the credential itself was
//! refused (for example, the owner regenerated the license token on
//! app.nano.rs and `.env` still holds the old one). Retrying never fixes that,
//! so unlike a network error or a 5xx it is recorded with the cached license
//! status and surfaced as a critical SIEM Health finding and an admin banner.
//!
//! Admission does not change: the install keeps its cached status, keeps
//! retrying every interval, and locks only when the existing 14-day bound
//! after the last successful check-in passes. The next successful check-in
//! clears the record. The token is never stored, logged or displayed.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::checker::STALE_LICENSE_DAYS;
use crate::siem_health::types::{AnalysisResult, Recommendation};

/// Stable SIEM Health finding title (suppressions key on the title, so the
/// lock date lives in the description only).
pub const TOKEN_REJECTED_FINDING_TITLE: &str = "License token rejected by app.nano.rs";

/// Whether a check-in response means nano-main refused the credential.
///
/// nano-main answers a bad or regenerated token with 401. A 403 counts only
/// when its body is nano-main's JSON error shape (`{"error": "…"}`); any
/// other 403 (an HTML page from a TLS-inspecting proxy, a WAF or a CDN) or a
/// 407 comes from something between this install and nano-main, so telling
/// the admin to rotate a working token would be wrong. Those stay transient.
pub fn is_credential_rejection(status: reqwest::StatusCode, body: &str) -> bool {
    match status {
        reqwest::StatusCode::UNAUTHORIZED => true,
        reqwest::StatusCode::FORBIDDEN => is_nano_main_error_body(body),
        _ => false,
    }
}

/// Whether a refusal looks like it came from a proxy, WAF or CDN between
/// this install and nano-main rather than from nano-main itself.
pub fn is_intermediary_refusal(status: reqwest::StatusCode, body: &str) -> bool {
    status == reqwest::StatusCode::PROXY_AUTHENTICATION_REQUIRED
        || (status == reqwest::StatusCode::FORBIDDEN && !is_nano_main_error_body(body))
}

fn is_nano_main_error_body(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("error").map(serde_json::Value::is_string))
        .unwrap_or(false)
}

/// When an online install locks if no check-in succeeds before then:
/// [`STALE_LICENSE_DAYS`] after the last successful check-in. `None` when the
/// install never completed one (it is already failing closed).
pub fn lock_date(last_successful_check_in: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    last_successful_check_in.map(|last| last + chrono::Duration::days(STALE_LICENSE_DAYS))
}

/// The persisted fact (in `license_status.raw_response.token_rejected`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRejection {
    pub http_status: u16,
    /// First rejection since the last successful check-in.
    pub first_rejected_at: DateTime<Utc>,
    pub last_rejected_at: DateTime<Utc>,
}

impl TokenRejection {
    pub fn new(http_status: u16, at: DateTime<Utc>) -> Self {
        Self {
            http_status,
            first_rejected_at: at,
            last_rejected_at: at,
        }
    }
}

/// What the banner and the SIEM Health finding show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenRejectedNotice {
    pub http_status: u16,
    pub first_rejected_at: DateTime<Utc>,
    pub last_rejected_at: DateTime<Utc>,
    /// `None` when the install never checked in successfully.
    pub locks_at: Option<DateTime<Utc>>,
    pub message: String,
}

impl TokenRejectedNotice {
    pub fn new(rejection: TokenRejection, last_successful_check_in: Option<DateTime<Utc>>) -> Self {
        let locks_at = lock_date(last_successful_check_in);
        Self {
            http_status: rejection.http_status,
            first_rejected_at: rejection.first_rejected_at,
            last_rejected_at: rejection.last_rejected_at,
            locks_at,
            message: message(locks_at),
        }
    }
}

/// The operator-facing message.
pub fn message(locks_at: Option<DateTime<Utc>>) -> String {
    const HEAD: &str = "License token was rejected by app.nano.rs. Update LICENSE_TOKEN in .env \
                        and re-run ./install.sh.";
    match locks_at {
        Some(at) => format!(
            "{HEAD} This install locks on {} ({STALE_LICENSE_DAYS} days after the last \
             successful check-in).",
            at.format("%Y-%m-%d %H:%M UTC")
        ),
        None => format!(
            "{HEAD} This install has never completed a successful check-in, so licensed \
             features stay locked until one succeeds."
        ),
    }
}

/// The critical SIEM Health finding for a recorded rejection.
pub fn recommendation(notice: &TokenRejectedNotice) -> Recommendation {
    Recommendation {
        title: TOKEN_REJECTED_FINDING_TITLE.to_string(),
        description: format!(
            "{} The license server has answered HTTP {} to every check-in since {}. \
             Check-ins keep retrying; this finding clears after the next successful one.",
            notice.message,
            notice.http_status,
            notice.first_rejected_at.format("%Y-%m-%d %H:%M UTC"),
        ),
        priority: "critical".to_string(),
    }
}

/// Insert the finding (idempotent) and cap the score at critical, like the
/// other deterministic findings. `None` adds nothing.
pub fn ensure_token_rejected_finding(
    analysis: &mut AnalysisResult,
    notice: Option<&TokenRejectedNotice>,
) {
    let Some(notice) = notice else {
        return;
    };
    analysis.overall_score = analysis.overall_score.min(49);
    let rec = recommendation(notice);
    if !analysis.recommendations.iter().any(|r| r.title == rec.title) {
        analysis.recommendations.insert(0, rec);
    }
}

#[cfg(test)]
#[path = "token_rejection_tests.rs"]
mod tests;
