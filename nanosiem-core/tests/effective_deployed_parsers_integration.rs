// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2304 (Finding A): what the Vector renderer is allowed to deploy.
//!
//! Both the direct-deploy path and the publication reconciler now render from
//! `list_effective_deployed_parsers`. These tests pin the two properties that
//! made the difference between shipping a published parser and shipping
//! whatever happened to be in the editor:
//!
//!   * the ACTIVE `log_source_versions` row wins over the working copy, and
//!   * every deployment-affecting column survives the round trip.
//!
//! Plus the revision fence: activating a version has to move `source_revision`,
//! or the reconciler never notices that the deployed artefact changed.

use nanosiem_core::parsers::list_effective_deployed_parsers;
use nanosiem_core::schema::SCHEMA_PROFILE_ENV;
use nanosiem_core::{VectorConfigPublicationError, VectorConfigPublisher};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

/// Enough of the real schema for migrations 229 and 283 to apply and for the
/// canonical query to project every column it reads. Mirrors the table subset
/// in `vector_config_publication_integration.rs`; `log_source_versions` is the
/// addition this suite is about.
const SOURCE_TABLES: &str = r#"
CREATE TABLE log_sources (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL, description TEXT, source_type TEXT NOT NULL,
    source_config JSONB, credential_id UUID,
    parser_vrl TEXT NOT NULL, output_fields JSONB,
    match_values TEXT[], enabled BOOLEAN NOT NULL DEFAULT FALSE,
    validated BOOLEAN NOT NULL DEFAULT FALSE, validation_error TEXT,
    category TEXT, vendor TEXT, product TEXT,
    namespace TEXT NOT NULL DEFAULT 'default', timezone TEXT NOT NULL DEFAULT 'UTC',
    sampling_ratio DOUBLE PRECISION, sampling_exclude_condition TEXT,
    extension_vrl TEXT, extension_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    dispatch_source_config_id UUID, kind TEXT NOT NULL DEFAULT 'log',
    enrich_kind TEXT, enrich_source TEXT, target_table TEXT, normalize_vrl TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE log_source_versions (
    id SERIAL PRIMARY KEY,
    log_source_id UUID NOT NULL REFERENCES log_sources(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    parser_vrl TEXT NOT NULL,
    output_fields JSONB,
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    change_reason TEXT NOT NULL,
    reverted_from_version INTEGER,
    extension_vrl TEXT,
    extension_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT uq_log_source_version UNIQUE (log_source_id, version_number)
);
CREATE TABLE source_configurations (
    id UUID PRIMARY KEY,
    name TEXT, config_type TEXT, connection_config JSONB, credential_id UUID,
    enabled BOOLEAN, deployed BOOLEAN
);
CREATE TABLE routing_rules (id UUID PRIMARY KEY, source_configuration_id UUID);
CREATE TABLE cloud_credentials (
    id UUID PRIMARY KEY,
    name TEXT, provider TEXT, credentials_encrypted BYTEA, nonce TEXT,
    region TEXT, active_version INTEGER
);
"#;

async fn isolated_pool() -> (PgPool, PgPool, String) {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must reference a disposable PostgreSQL database");
    let admin = PgPool::connect(&url)
        .await
        .expect("connect test PostgreSQL");
    let schema = format!("effective_parsers_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .expect("create isolated schema");

    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {search_path}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("connect isolated pool");

    sqlx::raw_sql(SOURCE_TABLES)
        .execute(&pool)
        .await
        .expect("create source tables");
    sqlx::raw_sql(include_str!(
        "../../migrations/postgres/229_vector_config_publication.sql"
    ))
    .execute(&pool)
    .await
    .expect("apply Vector publication migration");
    sqlx::raw_sql(include_str!(
        "../../migrations/postgres/284_vector_config_publication_fidelity.sql"
    ))
    .execute(&pool)
    .await
    .expect("apply publication fidelity migration");
    (admin, pool, schema)
}

async fn drop_schema(admin: &PgPool, pool: PgPool, schema: &str) {
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(admin)
        .await
        .expect("drop isolated schema");
}

async fn source_revision(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT source_revision FROM vector_config_publication_state WHERE singleton = TRUE",
    )
    .fetch_one(pool)
    .await
    .expect("read source revision")
}

/// A log source whose working copy is a half-finished draft, carrying sampling
/// and an extension overlay.
async fn insert_draft_source(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO log_sources \
         (id, name, source_type, parser_vrl, output_fields, enabled, validated, \
          sampling_ratio, sampling_exclude_condition, extension_vrl, extension_enabled) \
         VALUES ($1, 'apache', 'apache', '.draft = true', '{\"draft\": 1}'::JSONB, TRUE, TRUE, \
                 0.25, '.action != \"allow\"', '.overlay = \"draft\"', TRUE)",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("insert log source");
    id
}

async fn activate_version(
    pool: &PgPool,
    log_source_id: Uuid,
    version_number: i32,
    parser_vrl: &str,
    extension_vrl: Option<&str>,
    extension_enabled: bool,
) {
    sqlx::query("UPDATE log_source_versions SET is_active = FALSE WHERE log_source_id = $1")
        .bind(log_source_id)
        .execute(pool)
        .await
        .expect("deactivate previous versions");
    sqlx::query(
        "INSERT INTO log_source_versions \
         (log_source_id, version_number, parser_vrl, output_fields, is_active, change_reason, \
          extension_vrl, extension_enabled) \
         VALUES ($1, $2, $3, '{\"published\": 1}'::JSONB, TRUE, 'publish', $4, $5)",
    )
    .bind(log_source_id)
    .bind(version_number)
    .bind(parser_vrl)
    .bind(extension_vrl)
    .bind(extension_enabled)
    .execute(pool)
    .await
    .expect("insert active version");
}

/// The headline defect: publication rendered `log_sources.parser_vrl`, the
/// editor's working copy. A save nobody chose to deploy bumped
/// `source_revision` (those columns are migration-229 trigger inputs) and the
/// 5s reconciler shipped the draft to every managed tenant's Vector.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn deploy_renders_the_active_version_not_the_working_draft() {
    let (admin, pool, schema) = isolated_pool().await;
    let id = insert_draft_source(&pool).await;
    activate_version(
        &pool,
        id,
        1,
        ".published = true",
        Some(".overlay = \"published\""),
        true,
    )
    .await;

    let parsers = list_effective_deployed_parsers(&pool)
        .await
        .expect("load effective deployed parsers");
    let parser = parsers
        .iter()
        .find(|p| p.id == id)
        .expect("the log source must be present");

    assert_eq!(
        parser.parser_vrl, ".published = true",
        "the deployed VRL must come from the active version, never the draft",
    );
    assert_eq!(
        parser.extension_vrl.as_deref(),
        Some(".overlay = \"published\""),
        "the extension is part of the published version, not the draft",
    );
    assert_eq!(
        parser.output_fields,
        Some(serde_json::json!({"published": 1})),
        "output_fields must follow the active version too",
    );

    drop_schema(&admin, pool, &schema).await;
}

/// The second consequence: the publication query omitted `sampling_*` and
/// `extension_*` entirely, and `row_to_parser` defaults absent columns OFF — so
/// publishing DELETED a live sampling or extension transform that the direct
/// deploy path had emitted.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn every_deployment_affecting_column_survives_the_projection() {
    let (admin, pool, schema) = isolated_pool().await;
    let id = insert_draft_source(&pool).await;
    activate_version(&pool, id, 1, ".published = true", None, false).await;

    let parsers = list_effective_deployed_parsers(&pool).await.unwrap();
    let parser = parsers.iter().find(|p| p.id == id).unwrap();

    assert_eq!(
        parser.sampling_ratio,
        Some(0.25),
        "dropping sampling_ratio silently multiplies a tenant's ingest volume",
    );
    assert_eq!(
        parser.sampling_exclude_condition.as_deref(),
        Some(".action != \"allow\""),
        "the sampling exclusion is what keeps deny events unsampled",
    );

    // The active version published NO extension, so the overlay must be off —
    // even though the working copy still has one enabled.
    assert_eq!(parser.extension_vrl, None);
    assert!(!parser.extension_enabled);

    drop_schema(&admin, pool, &schema).await;
}

/// A source that has never been published has no active version; the working
/// copy is the only definition there is. Pre-versioning rows must keep
/// deploying rather than rendering as an empty parser.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn unpublished_source_falls_back_to_the_working_copy() {
    let (admin, pool, schema) = isolated_pool().await;
    let id = insert_draft_source(&pool).await;

    let parsers = list_effective_deployed_parsers(&pool).await.unwrap();
    let parser = parsers.iter().find(|p| p.id == id).unwrap();

    assert_eq!(parser.parser_vrl, ".draft = true");
    assert_eq!(parser.extension_vrl.as_deref(), Some(".overlay = \"draft\""));
    assert!(parser.extension_enabled);

    drop_schema(&admin, pool, &schema).await;
}

/// Two rows active at once must not multiply the log source into duplicate
/// parsers — that would trip the NAN-2247 source_type collision guard and
/// block every deploy until someone found the stray row. The partial index on
/// `log_source_versions` is not unique, so only the LATERAL … LIMIT 1 prevents
/// it. Highest version number wins.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn concurrently_active_versions_cannot_duplicate_a_parser() {
    let (admin, pool, schema) = isolated_pool().await;
    let id = insert_draft_source(&pool).await;
    activate_version(&pool, id, 1, ".v1 = true", None, false).await;
    // Bypass the deactivation the service performs, simulating a torn write.
    sqlx::query(
        "INSERT INTO log_source_versions \
         (log_source_id, version_number, parser_vrl, is_active, change_reason) \
         VALUES ($1, 2, '.v2 = true', TRUE, 'publish')",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    let parsers = list_effective_deployed_parsers(&pool).await.unwrap();
    assert_eq!(
        parsers.iter().filter(|p| p.id == id).count(),
        1,
        "one log source must always render as exactly one parser",
    );
    assert_eq!(parsers[0].parser_vrl, ".v2 = true");

    drop_schema(&admin, pool, &schema).await;
}

/// The fence half of the fix. Now that the renderer reads the active version,
/// publishing one has to advance `source_revision` — otherwise the reconciler
/// sees no change and the published parser never reaches Vector. Migration 229
/// fenced only the working-copy columns, which is exactly backwards.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn activating_a_version_advances_the_source_revision() {
    let (admin, pool, schema) = isolated_pool().await;
    let id = insert_draft_source(&pool).await;

    let before_publish = source_revision(&pool).await;
    activate_version(&pool, id, 1, ".v1 = true", None, false).await;
    let after_publish = source_revision(&pool).await;
    assert!(
        after_publish > before_publish,
        "publishing a version must be visible to the publication reconciler",
    );

    // Reverting/activating an EXISTING row is an is_active UPDATE, not an
    // insert, and must fence too.
    sqlx::query(
        "INSERT INTO log_source_versions \
         (log_source_id, version_number, parser_vrl, is_active, change_reason) \
         VALUES ($1, 2, '.v2 = true', FALSE, 'publish')",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    let before_activate = source_revision(&pool).await;
    sqlx::query(
        "UPDATE log_source_versions SET is_active = (version_number = 2) WHERE log_source_id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        source_revision(&pool).await > before_activate,
        "flipping which version is active must advance the revision fence",
    );

    drop_schema(&admin, pool, &schema).await;
}

async fn bundle(
    publisher: &VectorConfigPublisher,
    root: &std::path::Path,
    value: &str,
) -> nanosiem_core::SnapshotBundle {
    let sources = root.join("sources");
    tokio::fs::create_dir_all(sources.join("parsers"))
        .await
        .unwrap();
    tokio::fs::write(
        sources.join("parsers/test.toml"),
        format!("[transforms.test]\ntype = \"filter\"\ncondition = \"{value}\"\n"),
    )
    .await
    .unwrap();
    publisher.prepare_snapshot(sources).await.unwrap()
}

/// NAN-2304 (Finding B), the case the fingerprint itself creates.
///
/// Renderer epochs and semantic versions are totally ordered, so before this
/// change a superseded renderer never reached the insert and the
/// `(revision, epoch, version)` uniqueness key was never contended.
/// Fingerprints are deliberately UNORDERED — the running renderer always wins,
/// so a deployment mid-flip converges on the profile its pods actually have —
/// which means two renderers can leapfrog the pointer at one revision. The
/// second time a given identity publishes there it must adopt the generation it
/// already owns instead of colliding with itself: a raw unique violation would
/// leave BOTH renderers unable to publish for as long as the disagreement
/// lasted.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn leapfrogging_renderers_adopt_their_own_generation_instead_of_colliding() {
    let (admin, pool, schema) = isolated_pool().await;
    let dir = tempfile::tempdir().unwrap();
    let publisher = VectorConfigPublisher::new(pool.clone(), dir.path(), "flip-node");
    let revision = publisher.source_revision().await.unwrap();

    std::env::set_var(SCHEMA_PROFILE_ENV, "udm");
    let udm = bundle(&publisher, dir.path(), "udm").await;
    let udm_generation = publisher
        .publish(revision, &udm)
        .await
        .expect("first publish")
        .generation()
        .expect("a generation must be committed");

    std::env::set_var(SCHEMA_PROFILE_ENV, "ocsf");
    let ocsf = bundle(&publisher, dir.path(), "ocsf").await;
    let ocsf_generation = publisher
        .publish(revision, &ocsf)
        .await
        .expect("an env-only profile flip must publish, not fail as a divergent render")
        .generation()
        .expect("a generation must be committed");
    assert_ne!(
        ocsf_generation, udm_generation,
        "the OCSF render must not be filed under the UDM generation",
    );

    // The other replica, still on UDM, renders again at the same revision.
    std::env::set_var(SCHEMA_PROFILE_ENV, "udm");
    let udm_again = bundle(&publisher, dir.path(), "udm").await;
    let readopted = publisher
        .publish(revision, &udm_again)
        .await
        .expect("a renderer must be able to republish its own identity")
        .generation()
        .expect("a generation must be committed");
    assert_eq!(
        readopted, udm_generation,
        "the identity's existing generation must be adopted, not duplicated",
    );

    // Adoption must not become a way to smuggle different bytes under an
    // identity that already committed.
    let tampered = bundle(&publisher, dir.path(), "udm-but-different").await;
    assert!(
        matches!(
            publisher.publish(revision, &tampered).await,
            Err(VectorConfigPublicationError::DivergentRender { .. })
        ),
        "one renderer identity must still mean one set of bytes per revision",
    );

    std::env::remove_var(SCHEMA_PROFILE_ENV);
    drop_schema(&admin, pool, &schema).await;
}
