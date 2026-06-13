// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1432 — `LOWERCASE_NORMALIZED_FIELDS` data-contract check against a live
//! ClickHouse.
//!
//! The SQL generator compares every field in `LOWERCASE_NORMALIZED_FIELDS`
//! with raw equality (`"user" = 'dan lussier'`, no `lower()` wrapper) so the
//! raw-column indexes prune. That is only correct if **every writer** stores
//! those columns lowercase. The contract was silently broken once already: the
//! audit emitter stored display-case actor names ('Dan Lussier'), so
//! `user="dan lussier"` found 0 audit rows (QUERY_PERF_AUDIT.md B6).
//!
//! This test asserts `countIf(f != lower(f)) = 0` per field over rows written
//! after the contract-effective cutoff, so a future writer that breaks the
//! precondition turns this red instead of silently losing search results.
//!
//! The field list is enumerated **dynamically** from the public `UdmProfile`
//! (which `schema::tests::lowercase_normalized_fields_match_const` locks to
//! the `LOWERCASE_NORMALIZED_FIELDS` const), so new members — e.g. `src_user`,
//! added in NAN-1415 — are picked up without editing this file.
//!
//! Rows **before** the cutoff are excluded on purpose: NAN-1432 chose NOT to
//! destructively normalize historical data (display-case audit rows written by
//! the pre-fix emitter remain as-is; a scoped one-off normalization of
//! `source_type='audit'` rows is a possible follow-up that needs its own
//! review). The cutoff is the documented boundary of that historical gap.
//!
//! `#[ignore]`-gated (data-dependent: a deployment running a pre-fix binary
//! legitimately fails it). Run against the local dev stack:
//!   docker-compose up -d clickhouse
//!   cargo test -p nanosiem-core --test lowercase_contract_integration -- --ignored --nocapture

use nanosiem_core::schema::{SchemaProfile, UdmProfile};

/// Contract-effective date: the day the NAN-1432 audit-writer fix landed.
/// Rows older than this are the accepted historical gap (see module docs).
const CONTRACT_CUTOFF_UTC: &str = "2026-06-13 00:00:00";

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}
fn ch_user() -> String {
    std::env::var("CLICKHOUSE_TEST_USER").unwrap_or_else(|_| "nanosiem".into())
}
fn ch_pass() -> String {
    std::env::var("CLICKHOUSE_TEST_PASSWORD").unwrap_or_else(|_| "nanosiem".into())
}
fn ch_db() -> String {
    std::env::var("CLICKHOUSE_TEST_DB").unwrap_or_else(|_| "nanosiem".into())
}

/// Execute one read-only statement; returns the response body, or Err with
/// ClickHouse's message.
async fn exec(client: &reqwest::Client, sql: &str) -> Result<String, String> {
    let resp = client
        .post(ch_url())
        .basic_auth(ch_user(), Some(ch_pass()))
        .body(sql.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("HTTP {status}: {body}"))
    }
}

async fn reachable(client: &reqwest::Client) -> bool {
    exec(client, "SELECT 1")
        .await
        .map(|b| b.trim() == "1")
        .unwrap_or(false)
}

#[tokio::test]
#[ignore = "data-contract check against a live ClickHouse logs table; run with --ignored"]
async fn lowercase_normalized_fields_hold_on_live_data() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return;
    }
    let client = reqwest::Client::new();
    if !reachable(&client).await {
        eprintln!(
            "Skipping: ClickHouse not reachable at {} (start: docker-compose up -d clickhouse)",
            ch_url()
        );
        return;
    }

    // Enumerate the contract fields from the public profile — the canonical
    // const is locked to this by `lowercase_normalized_fields_match_const`.
    // (`sourcetype` is a pure query-layer alias of `source_type`, not a profile
    // field, so enumerating the profile yields exactly the physical/ALIAS
    // columns that exist on `logs`.)
    let profile = UdmProfile::new();
    let fields: Vec<&str> = profile
        .fields()
        .iter()
        .map(|f| f.name)
        .filter(|name| profile.is_lowercased_at_ingest(name))
        .collect();

    // Sanity: the enumeration must actually carry the contract set, including
    // members added after this test was written (src_user joined in NAN-1415).
    assert!(
        fields.contains(&"user") && fields.contains(&"src_user"),
        "profile enumeration lost expected LOWERCASE_NORMALIZED_FIELDS members; got: {fields:?}"
    );

    let db = ch_db();
    let exprs = fields
        .iter()
        .map(|f| format!("countIf(`{f}` != lower(`{f}`))"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT {exprs} FROM {db}.logs \
         WHERE timestamp >= toDateTime64('{CONTRACT_CUTOFF_UTC}', 6) \
         FORMAT TSV"
    );

    let body = exec(&client, &sql).await.expect("contract query failed");
    let counts: Vec<u64> = body
        .trim()
        .split('\t')
        .map(|v| v.parse().expect("count parse"))
        .collect();
    assert_eq!(counts.len(), fields.len(), "column/field mismatch");

    let mut violations: Vec<String> = Vec::new();
    for (field, count) in fields.iter().zip(&counts) {
        if *count == 0 {
            continue;
        }
        // Attribute the violation to its writer(s) so the failure is
        // actionable without re-querying by hand.
        let diag_sql = format!(
            "SELECT source_type, count() FROM {db}.logs \
             WHERE timestamp >= toDateTime64('{CONTRACT_CUTOFF_UTC}', 6) \
               AND `{field}` != lower(`{field}`) \
             GROUP BY source_type ORDER BY count() DESC LIMIT 10 FORMAT TSV"
        );
        let by_source = exec(&client, &diag_sql).await.unwrap_or_else(|e| e);
        violations.push(format!(
            "`{field}`: {count} mixed-case row(s) since {CONTRACT_CUTOFF_UTC}, by source_type:\n{by_source}"
        ));
    }

    assert!(
        violations.is_empty(),
        "LOWERCASE_NORMALIZED_FIELDS contract broken — a writer is storing \
         mixed-case values in raw-equality-compared columns, so `field=\"value\"` \
         searches will silently miss those rows (NAN-1432):\n{}",
        violations.join("\n")
    );

    eprintln!(
        "Contract holds: {} fields clean since {CONTRACT_CUTOFF_UTC}",
        fields.len()
    );
}
