// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5390: SIEM Health flags ClickHouse refusing nano's own logins or writes.
//!
//! The v2.0.20 GKE burn locked every nano ClickHouse user out with a wrong
//! `clickhouse.allowedNetworks`: pods stayed Ready, `/api/health` answered 200
//! and SIEM Health reported nothing, while every Vector write was refused (and,
//! before Vector `0.61.0-nano.12`, dropped). This module turns the evidence
//! ClickHouse keeps into one critical finding:
//!
//! * logins refused for nano's own users (`nanosiem*`), codes 192-195/516:
//!   counted per user from `system.session_log` (LoginFailure) when the server
//!   keeps it (Compose), else from `system.errors` whose last message names a
//!   nano user (Helm keeps no session_log);
//! * `system.query_log`: INSERTs by nano's writer users refused for missing
//!   grants (497);
//! * the probe client's own login refused (it then cannot read either table).
//!
//! All within the last [`WINDOW_MINUTES`] minutes, at least [`MIN_HITS`] per
//! source (one operator typo or a stale credential is not a lockout), and
//! only on a server up longer than the window: `system.errors` is cumulative
//! and a fresh tenant's first boot can log a few refusals (noise, not a
//! lockout).

use serde::Deserialize;

use super::types::{AnalysisResult, Recommendation};

/// Title of the finding (stable: suppressions key on it).
pub const CLICKHOUSE_REFUSALS_TITLE: &str = "ClickHouse is refusing logins or nano's writes";

/// Look-back window. SIEM Health runs far less often, so this reports a
/// refusal that is ongoing (or just ended) when the report runs, not history.
pub const WINDOW_MINUTES: u32 = 15;

/// UNKNOWN_USER, WRONG_PASSWORD, REQUIRED_PASSWORD, IP_ADDRESS_NOT_ALLOWED,
/// AUTHENTICATION_FAILED.
pub const AUTH_REFUSAL_CODES: [i32; 5] = [192, 193, 194, 195, 516];

/// ACCESS_DENIED.
pub const ACCESS_DENIED_CODE: i32 = 497;

/// The users nano writes events with (Vector, direct OCSF writers, the app).
const WRITER_USERS: [&str; 3] = ["nanosiem_vector", "nanosiem_ingest", "nanosiem"];

/// Fewest refusals from one source that count as a lockout.
pub const MIN_HITS: u64 = 2;

#[derive(Debug, clickhouse::Row, Deserialize)]
struct ErrorRow {
    name: String,
    code: i32,
    value: u64,
    last_error_message: String,
}

#[derive(Debug, clickhouse::Row, Deserialize)]
struct LoginFailureRow {
    user: String,
    failures: u64,
}

#[derive(Debug, clickhouse::Row, Deserialize)]
struct DeniedInsertRow {
    user: String,
    refused: u64,
}

/// The ClickHouse error code at the start of a ClickHouse error message
/// (`Code: 516. DB::Exception: …`), anywhere in `message`.
pub fn clickhouse_error_code(message: &str) -> Option<i32> {
    let rest = &message[message.find("Code: ")? + "Code: ".len()..];
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    rest[..digits].parse().ok()
}

/// A finding line when `error` (from a query nano itself ran) is a login refusal.
pub fn refusal_from_error(error: &str) -> Option<String> {
    let code = clickhouse_error_code(error)?;
    AUTH_REFUSAL_CODES
        .contains(&code)
        .then(|| format!("nano's own ClickHouse login is refused: {}", truncate(error, 300)))
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Reads the refusals of the last [`WINDOW_MINUTES`] minutes. Like
/// `open_clickhouse_users`, it needs the admin identity: with the runtime-user
/// fallback it returns nothing instead of issuing queries that would be denied.
pub async fn clickhouse_refusals(
    system_probe_client: &clickhouse::Client,
) -> Result<Vec<String>, clickhouse::error::Error> {
    let current: String = system_probe_client.query("SELECT currentUser()").fetch_one().await?;
    let runtime = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "nanosiem".into());
    if current == runtime {
        return Ok(Vec::new());
    }
    let uptime: u64 = system_probe_client.query("SELECT toUInt64(uptime())").fetch_one().await?;
    if uptime < u64::from(WINDOW_MINUTES) * 60 {
        return Ok(Vec::new());
    }
    // System log tables exist only when the server config enables them
    // (Compose enables session_log; Helm does not).
    let (has_session_log, has_query_log): (u8, u8) = system_probe_client
        .query(
            "SELECT countIf(name = 'session_log') > 0, countIf(name = 'query_log') > 0 \
             FROM system.tables WHERE database = 'system'",
        )
        .fetch_one()
        .await?;
    let (logins, errors) = if has_session_log != 0 {
        let rows = system_probe_client
            .query(&format!(
                "SELECT user, count() AS failures FROM system.session_log \
                 WHERE event_date >= yesterday() \
                 AND event_time > now() - INTERVAL {WINDOW_MINUTES} MINUTE \
                 AND type = 'LoginFailure' AND startsWith(user, 'nanosiem') \
                 GROUP BY user ORDER BY user"
            ))
            .fetch_all::<LoginFailureRow>()
            .await?;
        (rows, Vec::new())
    } else {
        let codes = AUTH_REFUSAL_CODES.map(|c| c.to_string()).join(", ");
        let rows = system_probe_client
            .query(&format!(
                "SELECT name, code, value, last_error_message FROM system.errors \
                 WHERE code IN ({codes}) AND remote = 0 \
                 AND last_error_time > now() - INTERVAL {WINDOW_MINUTES} MINUTE ORDER BY code"
            ))
            .fetch_all::<ErrorRow>()
            .await?;
        (Vec::new(), rows)
    };
    let writers = WRITER_USERS.map(|u| format!("'{u}'")).join(", ");
    let denied = if has_query_log == 0 {
        Vec::new()
    } else {
        system_probe_client
        .query(&format!(
            "SELECT user, count() AS refused FROM system.query_log \
             WHERE event_date >= yesterday() \
             AND event_time > now() - INTERVAL {WINDOW_MINUTES} MINUTE \
             AND type IN ('ExceptionBeforeStart', 'ExceptionWhileProcessing') \
             AND exception_code = {ACCESS_DENIED_CODE} AND query_kind = 'Insert' \
             AND user IN ({writers}) GROUP BY user ORDER BY user"
        ))
        .fetch_all::<DeniedInsertRow>()
        .await?
    };
    Ok(refusal_lines(&logins, &errors, &denied))
}

/// The nano user an AUTHENTICATION_FAILED-style message names
/// (`nanosiem_vector: Authentication failed: …`), if any.
fn nano_user_in_message(message: &str) -> Option<&str> {
    let (user, _) = message.trim_start().split_once(": ")?;
    (user.starts_with("nanosiem")
        && user.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
    .then_some(user)
}

/// Keeps only nano's users and sources with at least [`MIN_HITS`] refusals.
/// `system.errors` counts are cumulative since server start and keep one last
/// message per code, so a row counts only when that message (inside the
/// window, per the query) names a nano user; the total is reported as such.
/// IP_ADDRESS_NOT_ALLOWED (195) never names the user, but ClickHouse answers
/// the same login with AUTHENTICATION_FAILED (516), which does, and a locked
/// out Vector retries every few seconds, so its 516 stays the last message.
fn refusal_lines(
    logins: &[LoginFailureRow],
    errors: &[ErrorRow],
    denied: &[DeniedInsertRow],
) -> Vec<String> {
    let mut lines: Vec<String> = logins
        .iter()
        .filter(|l| l.user.starts_with("nanosiem") && l.failures >= MIN_HITS)
        .map(|l| format!("{} refused logins for {}", l.failures, l.user))
        .collect();
    lines.extend(
        errors
            .iter()
            .filter(|e| e.value >= MIN_HITS)
            .filter_map(|e| {
                let user = nano_user_in_message(&e.last_error_message)?;
                Some(format!(
                    "{} ({}) for {}, {} since ClickHouse started: last {}",
                    e.name,
                    e.code,
                    user,
                    e.value,
                    truncate(e.last_error_message.trim(), 300)
                ))
            }),
    );
    lines.extend(denied.iter().filter(|d| d.refused >= MIN_HITS).map(|d| {
        format!(
            "{} INSERTs by {} refused for missing grants (ACCESS_DENIED, 497)",
            d.refused, d.user
        )
    }));
    lines
}

/// Adds the critical finding (score capped at 49) when `lines` is not empty.
pub fn ensure_clickhouse_refusal_findings(analysis: &mut AnalysisResult, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    analysis.overall_score = analysis.overall_score.min(49);
    if analysis
        .recommendations
        .iter()
        .any(|r| r.title == CLICKHOUSE_REFUSALS_TITLE)
    {
        return;
    }
    analysis.recommendations.insert(
        0,
        Recommendation {
            title: CLICKHOUSE_REFUSALS_TITLE.to_string(),
            description: format!(
                "In the last {WINDOW_MINUTES} minutes ClickHouse refused logins or writes: {}. \
                 While this lasts, ingest still accepts events and Vector holds them in its disk \
                 buffer, retrying, until ClickHouse accepts them again; a full buffer pushes back \
                 on senders. Search and detections cannot read new data. Check the users' \
                 networks (Helm: clickhouse.allowedNetworks; Compose: re-run install.sh), the \
                 ClickHouse passwords in the nano Secret / .env, and the users' grants. On Helm, \
                 a corrected `helm upgrade` applies the users config before migrations run.",
                lines.join("; ")
            ),
            priority: "critical".to_string(),
        },
    );
}

#[cfg(test)]
#[path = "clickhouse_refusals_tests.rs"]
mod tests;
