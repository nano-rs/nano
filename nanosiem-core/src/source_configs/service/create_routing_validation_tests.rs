// SPDX-License-Identifier: AGPL-3.0-or-later
//! Inline routing rules on source-config create get the same write-time
//! validation as rules added one at a time (security review 2026-11-09,
//! NAN-5152).

use super::*;

fn rule(priority: i32, field: &str, match_type: &str, value: Option<&str>, target: &str) -> NewRoutingRule {
    NewRoutingRule {
        priority: Some(priority),
        match_field: field.to_string(),
        match_type: match_type.to_string(),
        match_value: value.map(str::to_string),
        target_source_type: target.to_string(),
    }
}

fn kafka_request(name: &str, rules: Vec<NewRoutingRule>) -> NewSourceConfiguration {
    NewSourceConfiguration {
        name: name.to_string(),
        description: None,
        config_type: "kafka".to_string(),
        connection_config: serde_json::json!({"bootstrap_servers": "kafka:9092", "topics": ["t"]}),
        credential_id: None,
        default_source_type: None,
        routing_rules: Some(rules),
    }
}

const INJECTED_FIELD: &str = "topic == \"x\" { .source_type = \"y\" }\nif true";

fn invalid_rules() -> Vec<NewRoutingRule> {
    vec![
        rule(10, INJECTED_FIELD, "exact", Some("x"), "y"),
        rule(10, "topic", "not_a_match_type", Some("x"), "y"),
        rule(10, "topic", "exact", Some("x\ny"), "y"),
        rule(10, "topic", "regex", Some("it's"), "y"),
    ]
}

#[test]
fn shared_validator_rejects_invalid_initial_rules() {
    for mut bad in invalid_rules() {
        let err = SourceConfigService::validate_new_routing_rule("kafka", &mut bad)
            .expect_err("invalid rule must be rejected");
        assert!(
            matches!(err, SourceConfigServiceError::InvalidConfig(_)),
            "rule {bad:?}: expected InvalidConfig, got {err:?}"
        );
    }
}

#[test]
fn shared_validator_coerces_like_create_rule() {
    // Pull-source rule on `source_type` collapses to default, as create_rule does.
    let mut r = rule(10, "source_type", "exact", Some("x"), "x");
    SourceConfigService::validate_new_routing_rule("kafka", &mut r).unwrap();
    assert_eq!(r.match_type, "default");
    let mut ok = rule(10, "headers.feed", "exact", Some("edr"), "edr");
    SourceConfigService::validate_new_routing_rule("kafka", &mut ok).unwrap();
    assert_eq!(ok.match_type, "exact");
}

/// DB-backed: an invalid create persists nothing; valid initial rules are
/// stored and rendered as before. Run with a throwaway Postgres:
/// `DATABASE_URL=… NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 NANOSIEM_ALLOW_DEFAULT_KEYS=true cargo test -p nanosiem-core --lib create_routing_validation_tests -- --ignored`
#[tokio::test]
#[ignore = "requires live Postgres"]
async fn create_with_initial_rules_against_postgres() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    assert!(
        matches!(std::env::var("NANOSIEM_ALLOW_DESTRUCTIVE_TESTS").as_deref(), Ok("1" | "true")),
        "set NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 for a disposable database"
    );
    let pool = PgPool::connect(&url).await.expect("connect test postgres");
    crate::db::run_postgres_migrations(&pool).await.expect("migrate");
    let service = SourceConfigService::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();

    // Every invalid rule shape fails the create.
    for (i, bad) in invalid_rules().into_iter().enumerate() {
        let name = format!("nan5152-bad{i}-{}", &suffix[suffix.len() - 10..]);
        let err = service
            .create(kafka_request(&name, vec![bad.clone()]), CredentialUseGrant::none())
            .await
            .expect_err("invalid initial rule must fail the create");
        assert!(
            matches!(err, SourceConfigServiceError::InvalidConfig(_)),
            "rule {bad:?}: expected InvalidConfig, got {err:?}"
        );
    }

    let bad_name = format!("nan5152-bad-{}", &suffix[suffix.len() - 10..]);
    let err = service
        .create(
            kafka_request(
                &bad_name,
                vec![
                    rule(10, "topic", "exact", Some("ok"), "ok"),
                    rule(20, INJECTED_FIELD, "exact", Some("x"), "y"),
                ],
            ),
            CredentialUseGrant::none(),
        )
        .await
        .expect_err("invalid initial rule must fail the create");
    assert!(matches!(err, SourceConfigServiceError::InvalidConfig(_)), "got {err:?}");
    let persisted: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM source_configurations WHERE name LIKE 'nan5152-bad%' AND name LIKE $1")
            .bind(format!("%{}", &suffix[suffix.len() - 10..]))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(persisted, 0, "nothing persisted for a rejected create");

    let good_name = format!("nan5152-good-{}", &suffix[suffix.len() - 10..]);
    let created = service
        .create(
            kafka_request(
                &good_name,
                vec![
                    rule(10, "headers.feed", "exact", Some("edr_feed"), "edr_feed"),
                    rule(1000, "topic", "default", None, "unknown"),
                ],
            ),
            CredentialUseGrant::none(),
        )
        .await
        .expect("valid initial rules create");
    let with_rules = service.get_with_rules(created.id).await.expect("read back");
    assert_eq!(with_rules.routing_rules.len(), 2);
    assert!(with_rules
        .routing_rules
        .iter()
        .any(|r| r.match_field == "headers.feed" && r.match_type == "exact"));
    let vrl = SourceConfigService::generate_routing_transform(&with_rules, "src", "route", false);
    assert!(
        vrl.contains("(to_string(.headers.feed) ?? \"\") == \"edr_feed\""),
        "initial rule rendered as before, got:\n{vrl}"
    );

    sqlx::query("DELETE FROM source_configurations WHERE id = $1")
        .bind(created.id)
        .execute(&pool)
        .await
        .unwrap();
}
