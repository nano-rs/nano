// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5136: disabling a provider must not destroy agents' model choices, and
//! must only move agents to a provider that can actually serve them.
//!
//! DB-backed: needs a disposable PostgreSQL at `NANOSIEM_TEST_DATABASE_URL`
//! and skips without one. Each test builds the three tables it touches in a
//! throwaway schema.

use super::*;

async fn pool() -> Option<PgPool> {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL").ok()?;
    let schema = format!("nan5136_{}", uuid::Uuid::new_v4().simple());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect({
            let schema = schema.clone();
            move |conn, _| {
                let schema = schema.clone();
                Box::pin(async move {
                    sqlx::Executor::execute(conn, format!("SET search_path TO {schema}").as_str())
                        .await
                        .map(|_| ())
                })
            }
        })
        .connect(&url)
        .await
        .expect("connect");
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema};
         CREATE TABLE {schema}.provider_credentials (
             provider TEXT PRIMARY KEY, display_name TEXT NOT NULL DEFAULT '',
             credentials_encrypted BYTEA, config JSONB DEFAULT '{{}}'::jsonb,
             enabled BOOLEAN DEFAULT false);
         CREATE TABLE {schema}.available_models (
             model_id TEXT PRIMARY KEY, provider TEXT NOT NULL,
             input_price_per_million REAL, deprecated BOOLEAN DEFAULT false);
         CREATE TABLE {schema}.agent_model_config (
             agent_id TEXT PRIMARY KEY, model_id TEXT NOT NULL,
             displaced_model_id TEXT, updated_at TIMESTAMPTZ DEFAULT now());"
    ))
    .execute(&pool)
    .await
    .expect("schema");
    Some(pool)
}

async fn exec(pool: &PgPool, sql: &str) {
    sqlx::raw_sql(sql).execute(pool).await.expect(sql);
}

async fn agents(pool: &PgPool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT agent_id, model_id, displaced_model_id FROM agent_model_config ORDER BY agent_id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Dan's local-stack sequence: agents on a model of provider A, A disabled,
/// A enabled again. The agents must end up exactly where they started.
#[tokio::test]
async fn disable_then_enable_restores_agent_models() {
    let Some(pool) = pool().await else { return };
    exec(
        &pool,
        "INSERT INTO provider_credentials (provider, credentials_encrypted, enabled) VALUES
             ('openai', '\\x01', true), ('anthropic', '\\x01', true);
         INSERT INTO available_models (model_id, provider, input_price_per_million) VALUES
             ('openai/qwen2.5:7b', 'openai', NULL),
             ('anthropic/claude-haiku', 'anthropic', 1.0);
         INSERT INTO agent_model_config (agent_id, model_id) VALUES
             ('query', 'openai/qwen2.5:7b'), ('summarize', 'openai/qwen2.5:7b'),
             ('detection', 'anthropic/claude-haiku');",
    )
    .await;

    // Disable openai.
    exec(&pool, "UPDATE provider_credentials SET enabled = false WHERE provider = 'openai'").await;
    let moved = migrate_agents_from_disabled_provider(&pool, "openai", true).await.unwrap();
    assert_eq!(moved, 2);
    let a = |id: &str, m: &str, d: Option<&str>| (id.to_string(), m.to_string(), d.map(str::to_string));
    assert_eq!(
        agents(&pool).await,
        vec![
            a("detection", "anthropic/claude-haiku", None),
            a("query", "anthropic/claude-haiku", Some("openai/qwen2.5:7b")),
            a("summarize", "anthropic/claude-haiku", Some("openai/qwen2.5:7b")),
        ]
    );

    // A second disable while still displaced must not overwrite the original.
    migrate_agents_from_unavailable_providers(&pool, true).await.unwrap();
    assert_eq!(agents(&pool).await[1].2.as_deref(), Some("openai/qwen2.5:7b"));

    // Enable openai again: restore, then the sweep must leave them alone.
    exec(&pool, "UPDATE provider_credentials SET enabled = true WHERE provider = 'openai'").await;
    assert_eq!(restore_displaced_agent_models(&pool, true).await.unwrap(), 2);
    assert_eq!(migrate_agents_from_unavailable_providers(&pool, true).await.unwrap(), 0);
    assert_eq!(
        agents(&pool).await,
        vec![
            a("detection", "anthropic/claude-haiku", None),
            a("query", "openai/qwen2.5:7b", None),
            a("summarize", "openai/qwen2.5:7b", None),
        ]
    );
}

/// The local-stack failure: the only other enabled provider was a keyless
/// Workers AI row with no gateway URL. It is enabled but cannot serve, so the
/// agents must stay put rather than move to a provider that fails every call.
#[tokio::test]
async fn unservable_fallback_moves_nothing() {
    let Some(pool) = pool().await else { return };
    exec(
        &pool,
        "INSERT INTO provider_credentials (provider, credentials_encrypted, enabled) VALUES
             ('openai', '\\x01', false), ('workers-ai', NULL, true);
         INSERT INTO available_models (model_id, provider, input_price_per_million) VALUES
             ('openai/qwen2.5:7b', 'openai', NULL),
             ('workers-ai/@cf/zai-org/glm-5.3', 'workers-ai', 0.1);
         INSERT INTO agent_model_config (agent_id, model_id) VALUES ('query', 'openai/qwen2.5:7b');",
    )
    .await;

    // No managed gateway URL: Workers AI cannot serve.
    assert_eq!(migrate_agents_from_disabled_provider(&pool, "openai", false).await.unwrap(), 0);
    assert_eq!(migrate_agents_from_unavailable_providers(&pool, false).await.unwrap(), 0);
    assert_eq!(agents(&pool).await[0].1, "openai/qwen2.5:7b");

    // With the gateway configured, Workers AI (credential-less) is servable.
    assert_eq!(migrate_agents_from_disabled_provider(&pool, "openai", true).await.unwrap(), 1);
}

/// A keyless self-hosted row with a base URL serves on its own, with no
/// managed gateway at all, so it is a valid fallback.
#[tokio::test]
async fn keyless_self_hosted_row_is_servable() {
    let Some(pool) = pool().await else { return };
    exec(
        &pool,
        "INSERT INTO provider_credentials (provider, credentials_encrypted, config, enabled) VALUES
             ('openai', '\\x01', '{}', false),
             ('self-hosted', NULL, '{\"base_url\": \"http://ollama:11434/v1\"}', true);
         INSERT INTO available_models (model_id, provider) VALUES
             ('openai/gpt-5', 'openai'), ('self-hosted/qwen2.5:0.5b', 'self-hosted');
         INSERT INTO agent_model_config (agent_id, model_id) VALUES ('query', 'openai/gpt-5');",
    )
    .await;
    assert_eq!(
        servable_fallback_model(&pool, false).await.unwrap().as_deref(),
        Some("self-hosted/qwen2.5:0.5b")
    );
}

/// Review finding: re-enabling a provider that still cannot serve (a stored
/// key but no base URL and no managed gateway) must not restore agents onto
/// it. They stay on the working fallback, and `displaced_model_id` survives
/// so a later fix to the provider still restores them.
#[tokio::test]
async fn reenabled_but_unservable_provider_keeps_the_fallback() {
    let Some(pool) = pool().await else { return };
    exec(
        &pool,
        "INSERT INTO provider_credentials (provider, credentials_encrypted, config, enabled) VALUES
             ('openai', '\\x01', '{}', true),
             ('self-hosted', NULL, '{\"base_url\": \"http://ollama:11434/v1\"}', true);
         INSERT INTO available_models (model_id, provider, input_price_per_million) VALUES
             ('openai/gpt-5', 'openai', 1.0), ('self-hosted/qwen2.5:0.5b', 'self-hosted', NULL);
         INSERT INTO agent_model_config (agent_id, model_id) VALUES ('query', 'openai/gpt-5');",
    )
    .await;

    // Self-run, no managed gateway: openai (gateway route) is unservable even
    // while enabled, so the sweep moves the agent to the self-hosted model.
    assert_eq!(migrate_agents_from_unavailable_providers(&pool, false).await.unwrap(), 1);
    let a = |m: &str, d: Option<&str>| ("query".to_string(), m.to_string(), d.map(str::to_string));
    assert_eq!(agents(&pool).await, vec![a("self-hosted/qwen2.5:0.5b", Some("openai/gpt-5"))]);

    // Re-saving openai with enabled:true changes nothing about servability.
    assert_eq!(restore_displaced_agent_models(&pool, false).await.unwrap(), 0);
    assert_eq!(migrate_agents_from_unavailable_providers(&pool, false).await.unwrap(), 0);
    assert_eq!(agents(&pool).await, vec![a("self-hosted/qwen2.5:0.5b", Some("openai/gpt-5"))]);

    // A blank key on a gateway route is unservable too, even with the gateway.
    exec(&pool, "UPDATE provider_credentials SET credentials_encrypted = NULL WHERE provider = 'openai'").await;
    assert_eq!(restore_displaced_agent_models(&pool, true).await.unwrap(), 0);

    // Once openai can actually serve (a direct base URL), the agent goes back.
    exec(
        &pool,
        "UPDATE provider_credentials SET config = '{\"base_url\": \"https://api.openai.com/v1\"}' \
         WHERE provider = 'openai'",
    )
    .await;
    assert_eq!(restore_displaced_agent_models(&pool, false).await.unwrap(), 1);
    assert_eq!(agents(&pool).await, vec![a("openai/gpt-5", None)]);
}
