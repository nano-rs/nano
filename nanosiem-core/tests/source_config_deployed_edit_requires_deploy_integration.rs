// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live-Postgres regression for NAN-5232: the Vector publication reconciler
//! renders every DEPLOYED source from its saved row and routing rules, so a
//! saved render-affecting edit to a deployed source is a deploy and needs
//! `source_configs:deploy`. Undeployed sources and non-rendered fields
//! (`description`, `enabled`) stay `source_configs:edit`-only.
//!
//! Run with:
//! `NANOSIEM_ALLOW_DEFAULT_KEYS=true cargo test -p nanosiem-core \
//!   --test source_config_deployed_edit_requires_deploy_integration -- --ignored --test-threads=1`

mod common;

use nanosiem_core::auth::CredentialUseGrant;
use nanosiem_core::source_configs::{
    NewRoutingRule, SourceConfigService, SourceConfigServiceError, UpdateRoutingRule,
    UpdateSourceConfiguration,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const BROKERS: &str = "kafka-1.corp.example:9093";

/// A `source_configs:edit` holder without `source_configs:deploy`.
const EDIT_ONLY: bool = false;
/// A `source_configs:deploy` holder.
const DEPLOYER: bool = true;

fn no_credentials() -> CredentialUseGrant {
    CredentialUseGrant::none()
}

fn conn(topic: &str) -> Value {
    json!({"bootstrap_servers": BROKERS, "group_id": "nano", "topics": [topic]})
}

async fn seed(pool: &PgPool, deployed: bool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO source_configurations
            (id, name, description, config_type, connection_config, enabled, deployed)
         VALUES ($1, $2, 'original', 'kafka', $3, TRUE, $4)",
    )
    .bind(id)
    .bind(format!("nan5232-{}", &id.simple().to_string()[..12]))
    .bind(conn("events"))
    .bind(deployed)
    .execute(pool)
    .await
    .expect("insert kafka source config");
    id
}

async fn stored(pool: &PgPool, id: Uuid) -> (Value, Option<String>) {
    sqlx::query_as("SELECT connection_config, description FROM source_configurations WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read source config")
}

async fn rule_count(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM routing_rules WHERE source_configuration_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count rules")
}

async fn cleanup(pool: &PgPool, id: Uuid) {
    sqlx::query("DELETE FROM source_configurations WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("clean source fixture");
}

fn retopic(topic: &str) -> UpdateSourceConfiguration {
    UpdateSourceConfiguration {
        connection_config: Some(conn(topic)),
        ..Default::default()
    }
}

fn rule(value: &str) -> NewRoutingRule {
    NewRoutingRule {
        priority: None,
        match_field: "source_type".to_string(),
        match_type: "exact".to_string(),
        match_value: Some(value.to_string()),
        target_source_type: value.to_string(),
    }
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn edit_only_cannot_change_rendered_config_of_deployed_source() {
    let pool = common::migrated_pool().await;
    let id = seed(&pool, true).await;
    let service = SourceConfigService::new(pool.clone());

    let err = service
        .update(id, retopic("other-topic"), no_credentials(), EDIT_ONLY)
        .await
        .expect_err("a connection change to a deployed source is a deploy");
    assert!(matches!(err, SourceConfigServiceError::DeployPermissionRequired), "got {err:?}");
    assert_eq!(stored(&pool, id).await.0, conn("events"), "nothing saved");

    let rename = UpdateSourceConfiguration {
        name: Some(format!("renamed-{}", &id.simple().to_string()[..8])),
        ..Default::default()
    };
    let err = service
        .update(id, rename, no_credentials(), EDIT_ONLY)
        .await
        .expect_err("a rename changes the rendered config and file path");
    assert!(matches!(err, SourceConfigServiceError::DeployPermissionRequired));

    let fallback = UpdateSourceConfiguration {
        default_source_type: Some("nan5232_feed".to_string()),
        ..Default::default()
    };
    let err = service
        .update(id, fallback, no_credentials(), EDIT_ONLY)
        .await
        .expect_err("default_source_type is rendered into the routing transform");
    assert!(matches!(err, SourceConfigServiceError::DeployPermissionRequired));

    cleanup(&pool, id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn edit_only_keeps_non_rendered_edits_on_deployed_source() {
    let pool = common::migrated_pool().await;
    let id = seed(&pool, true).await;
    let service = SourceConfigService::new(pool.clone());

    // The UI PUTs the whole object back: unchanged render inputs plus a new
    // description must pass.
    let whole_object = UpdateSourceConfiguration {
        description: Some("revised".to_string()),
        config_type: Some("kafka".to_string()),
        connection_config: Some(conn("events")),
        enabled: Some(true),
        ..Default::default()
    };
    service
        .update(id, whole_object, no_credentials(), EDIT_ONLY)
        .await
        .expect("description edit with echoed config is not a deploy");
    assert_eq!(stored(&pool, id).await.1.as_deref(), Some("revised"));

    cleanup(&pool, id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn deployer_and_undeployed_sources_are_unaffected() {
    let pool = common::migrated_pool().await;
    let service = SourceConfigService::new(pool.clone());

    let deployed = seed(&pool, true).await;
    service
        .update(deployed, retopic("other-topic"), no_credentials(), DEPLOYER)
        .await
        .expect("a deployer may change a deployed source");
    assert_eq!(stored(&pool, deployed).await.0, conn("other-topic"));

    let draft = seed(&pool, false).await;
    service
        .update(draft, retopic("other-topic"), no_credentials(), EDIT_ONLY)
        .await
        .expect("an undeployed source is edit-only");
    service
        .create_rule(draft, rule("nan5232_draft"), EDIT_ONLY)
        .await
        .expect("rules on an undeployed source are edit-only");

    cleanup(&pool, deployed).await;
    cleanup(&pool, draft).await;
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn edit_only_cannot_change_routing_rules_of_deployed_source() {
    let pool = common::migrated_pool().await;
    let id = seed(&pool, true).await;
    let service = SourceConfigService::new(pool.clone());

    let err = service
        .create_rule(id, rule("nan5232_new"), EDIT_ONLY)
        .await
        .expect_err("a rule on a deployed source goes live at the next publication");
    assert!(matches!(err, SourceConfigServiceError::DeployPermissionRequired), "got {err:?}");
    assert_eq!(rule_count(&pool, id).await, 0);

    let existing = service
        .create_rule(id, rule("nan5232_existing"), DEPLOYER)
        .await
        .expect("a deployer adds the rule");

    let patch = UpdateRoutingRule {
        target_source_type: Some("nan5232_elsewhere".to_string()),
        ..Default::default()
    };
    let err = service
        .update_rule(existing.id, patch, EDIT_ONLY)
        .await
        .expect_err("editing a deployed source's rule is a deploy");
    assert!(matches!(err, SourceConfigServiceError::DeployPermissionRequired));

    let err = service
        .delete_rule(existing.id, EDIT_ONLY)
        .await
        .expect_err("deleting a deployed source's rule is a deploy");
    assert!(matches!(err, SourceConfigServiceError::DeployPermissionRequired));

    let err = service
        .reorder_rules(id, vec![existing.id], EDIT_ONLY)
        .await
        .expect_err("reordering a deployed source's rules is a deploy");
    assert!(matches!(err, SourceConfigServiceError::DeployPermissionRequired));
    assert_eq!(rule_count(&pool, id).await, 1);

    service
        .delete_rule(existing.id, DEPLOYER)
        .await
        .expect("a deployer may delete the rule");

    cleanup(&pool, id).await;
}
