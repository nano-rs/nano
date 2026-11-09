// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5055: an AI allowance granted by the online licence check-in reaches
//! the meter that actually enforces credits (`charge_ai_credits` →
//! `get_tier_limits` → `increment_ai_credits`), not just a parsed struct.
//!
//! DB-backed: `#[ignore]`d so plain `cargo test` compiles but skips it; the
//! `pg-integration-tests` job runs it with `-- --ignored`. Single-threaded:
//! it rewrites the `system_settings` singleton and this month's AI counter.

mod common;

use nanosiem_core::{Entitlement, EntitlementEdition, EntitlementOperator, TierSettings};
use sqlx::PgPool;

async fn settings() -> (PgPool, TierSettings) {
    let pool = common::migrated_pool().await;
    (pool.clone(), TierSettings::new(pool))
}

async fn reset_month(pool: &PgPool) {
    let month = chrono::Utc::now().format("%Y-%m").to_string();
    sqlx::query("DELETE FROM ai_request_counts WHERE month = $1")
        .bind(month)
        .execute(pool)
        .await
        .expect("reset AI counter");
}

fn licensed(operator: EntitlementOperator) -> Entitlement {
    Entitlement {
        edition: EntitlementEdition::Licensed,
        operator,
        capacity_gb_per_day: Some(2.0),
    }
}

#[tokio::test]
#[ignore = "requires a disposable DATABASE_URL (pg-integration-tests)"]
async fn granted_allowance_is_enforced_and_clearing_restores_env_default() {
    assert!(
        std::env::var("NANO_AI_CREDITS_PER_MONTH").is_err(),
        "this suite asserts the unprovisioned hosted default"
    );
    let (pool, tier) = settings().await;
    tier.set_entitlement(licensed(EntitlementOperator::Hosted))
        .await
        .unwrap();

    // A normal hosted tenant with no grant and no provisioned ceiling: 0.
    tier.set_granted_ai_credits(None).await.unwrap();
    assert_eq!(tier.get_tier_limits().await.unwrap().ai_credits_per_month, Some(0));
    reset_month(&pool).await;
    assert!(tier.charge_ai_credits(10).await.is_err(), "no allowance, no AI");

    // An original tenant's grandfathered grant (3,000/month) is what the
    // meter enforces: exactly 3,000 is admitted, the next request is refused.
    tier.set_granted_ai_credits(Some(3_000)).await.unwrap();
    let limits = tier.get_tier_limits().await.unwrap();
    assert_eq!(limits.ai_credits_per_month, Some(3_000));
    assert!(limits.sso_enabled && limits.ha_enabled);
    reset_month(&pool).await;
    tier.charge_ai_credits(2_990).await.expect("within the grant");
    tier.charge_ai_credits(10).await.expect("reaches the grant exactly");
    assert!(tier.charge_ai_credits(10).await.is_err(), "past the grant");

    // A self-run deployment stays uncapped (customer-managed AI).
    tier.set_entitlement(licensed(EntitlementOperator::SelfRun))
        .await
        .unwrap();
    assert_eq!(tier.get_tier_limits().await.unwrap().ai_credits_per_month, None);

    // Revocation (next check-in without a grant) restores the default.
    tier.set_entitlement(licensed(EntitlementOperator::Hosted))
        .await
        .unwrap();
    tier.set_granted_ai_credits(None).await.unwrap();
    assert_eq!(tier.get_tier_limits().await.unwrap().ai_credits_per_month, Some(0));
    reset_month(&pool).await;
}

#[tokio::test]
#[ignore = "requires a disposable DATABASE_URL (pg-integration-tests)"]
async fn out_of_range_grants_are_refused_and_cannot_be_stored() {
    let (pool, tier) = settings().await;
    assert!(tier.set_granted_ai_credits(Some(0)).await.is_err());
    assert!(tier
        .set_granted_ai_credits(Some(i32::MAX as u32 + 1))
        .await
        .is_err());
    // The column CHECK backs the API validation.
    let direct = sqlx::query(
        "UPDATE system_settings SET entitlement_ai_credits_per_month = 0 WHERE id = 'default'",
    )
    .execute(&pool)
    .await;
    assert!(direct.is_err(), "CHECK rejects a zero allowance");
    tier.set_granted_ai_credits(None).await.unwrap();
}
