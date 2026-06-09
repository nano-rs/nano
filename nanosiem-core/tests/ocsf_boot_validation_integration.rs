// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! OCSF Phase 3b — boot-validation regression + fail-fast proof (NAN-1241).
//!
//! Two things the unit tests can't cover because they need a real table:
//!  1. REGRESSION: UDM boot validation MUST pass against the canonical
//!     `nanosiem.logs`. `PREWHERE_FIELDS` contains the alias `sourcetype` (not a
//!     physical column — it's an alias for `source_type`); requiring it verbatim
//!     would fail a perfectly healthy UDM boot. This test fails if that
//!     regression returns.
//!  2. FAIL-FAST PROOF: an OCSF profile pointed at a UDM table must ERROR at
//!     boot (missing OCSF columns), not silently return empty at query time.
//!
//! Requires local ClickHouse with `nanosiem.logs` present. Skips cleanly if
//! unreachable / table absent / SKIP_DB_TESTS set.

use nanosiem_core::schema::{validate_active_schema_table, OcsfProfile, UdmProfile};

fn client() -> clickhouse::Client {
    clickhouse::Client::default()
        .with_url(std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into()))
        .with_user(std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or_else(|_| "nanosiem_admin".into()))
        .with_password(
            std::env::var("CLICKHOUSE_ADMIN_PASSWORD")
                .unwrap_or_else(|_| "nanosiem_admin_secret".into()),
        )
}

/// Reachable AND `nanosiem.logs` exists — otherwise the test self-skips.
async fn logs_table_available(c: &clickhouse::Client) -> bool {
    match c
        .query("SELECT count() FROM system.columns WHERE database = 'nanosiem' AND table = 'logs'")
        .fetch_one::<u64>()
        .await
    {
        Ok(n) => n > 0,
        Err(_) => false,
    }
}

#[tokio::test]
async fn udm_boot_validation_passes_against_real_logs_table() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return;
    }
    let c = client();
    if !logs_table_available(&c).await {
        eprintln!("Skipping: ClickHouse unreachable or nanosiem.logs absent");
        return;
    }

    // The regression guard: a healthy UDM table must validate cleanly. Before the
    // canonicalize fix this failed on the `sourcetype` alias.
    let res = validate_active_schema_table(&c, &UdmProfile::new(), "nanosiem.logs").await;
    assert!(
        res.is_ok(),
        "UDM boot validation must pass against the real nanosiem.logs (alias columns \
         like `sourcetype` must not be required as physical columns): {res:?}"
    );
}

#[tokio::test]
async fn ocsf_profile_against_udm_table_fails_fast() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        return;
    }
    let c = client();
    if !logs_table_available(&c).await {
        eprintln!("Skipping: ClickHouse unreachable or nanosiem.logs absent");
        return;
    }

    // An OCSF deployment misconfigured to point at the UDM `logs` table must fail
    // boot (its dotted OCSF columns are absent), not silently return empty.
    let res = validate_active_schema_table(&c, &OcsfProfile::new(), "nanosiem.logs").await;
    assert!(
        res.is_err(),
        "OCSF profile against a UDM table must fail boot validation, got Ok"
    );
}
