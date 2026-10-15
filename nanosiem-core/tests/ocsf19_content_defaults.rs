// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3758: open core follows the first-party OCSF 1.9 catalogs by default.
//! NAN-3897: that content lives on `main`; the retired `ocsf-1.9` default
//! resolves to it.
//!
//! The fixture holds only the catalog PATHS at pinned upstream commits (no
//! parser or rule content ships in this repository); file bodies served to the
//! sync are synthetic.
use nanosiem_core::schema::{content_branch_for, default_content_branch_for, repo_path_for, select_ocsf_root_layout, SchemaId};

const PARSERS: usize = 67;
const RULES: usize = 144;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/ocsf19-catalog.json")).unwrap()
}

fn paths(fixture: &serde_json::Value, repo: &str) -> Vec<String> {
    fixture["catalogs"][repo]["paths"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_owned()).collect()
}

#[test]
fn fresh_repository_defaults_select_the_ocsf19_catalogs() {
    let fixture = fixture();
    for (repo, expected) in [("parsers", PARSERS), ("rules", RULES)] {
        let url = format!("https://github.com/nano-rs/{repo}");
        let stored = default_content_branch_for(&url, None);
        assert_eq!(stored, "main", "creation must store the default explicitly");
        assert_eq!(content_branch_for(&stored), fixture["branch"]);
        let paths = paths(&fixture, repo);
        let selected = if repo == "parsers" {
            let base = repo_path_for(SchemaId::Ocsf, "parsers/");
            paths.iter().filter(|p| p.starts_with(&base) && p.ends_with("/parser.yaml")).cloned().collect::<Vec<_>>()
        } else {
            assert_eq!(repo_path_for(SchemaId::Ocsf, ""), "");
            select_ocsf_root_layout(&paths).0
        };
        assert_eq!(selected.len(), expected);
    }
}

#[test]
fn creation_preserves_pins_and_third_parties() {
    for url in ["https://github.com/nano-rs/parsers", "github.com/nano-rs/rules.git", "https://github.com/NANO-RS/PARSERS/"] {
        assert_eq!(default_content_branch_for(url, None), "main");
        for pin in ["main", "my-fork", "legacy/clickhouse"] {
            assert_eq!(default_content_branch_for(url, Some(pin)), pin);
        }
        // The retired default is stored as what is synced.
        assert_eq!(default_content_branch_for(url, Some("ocsf-1.9")), "main");
    }
    for url in ["https://github.com/SigmaHQ/sigma", "https://github.com/nano-rs/playbooks", "https://example.com/nano-rs/parsers", "https://github.com/nano-rs/parsers/fork"] {
        assert_eq!(default_content_branch_for(url, None), "main");
        assert_eq!(default_content_branch_for(url, Some("ocsf-1.9")), "ocsf-1.9");
    }
    assert_eq!(content_branch_for("ocsf-1.9"), "main");
    assert_eq!(content_branch_for("main"), "main");
    assert_eq!(content_branch_for("my-fork"), "my-fork");
}

/// NAN-3897: migration 367 moves only first-party rows off the retired
/// `ocsf-1.9` branch, makes them due, and its URL match agrees with
/// `is_first_party_content_url`.
#[test]
fn content_follows_main_migrations_are_scoped_and_idempotent() {
    let core = include_str!("../../migrations/postgres/367_first_party_content_follows_main.sql");
    let code: String = core.lines().filter(|l| !l.trim_start().starts_with("--")).collect::<Vec<_>>().join("\n");
    assert!(!code.contains("THEN 'ocsf-1.9'"), "the insert trigger never defaults to the retired branch");
    assert!(code.contains("NEW.branch := 'main';"));
    for table in ["parser_repositories", "rule_repositories"] {
        let update = code.split(&format!("UPDATE public.{table}")).nth(1).expect(table);
        let update = &update[..update.find(';').unwrap()];
        assert!(update.contains("SET branch = 'main', last_synced_at = NULL, last_sync_commit = NULL"), "{table}");
        assert!(update.contains("WHERE btrim(branch) = 'ocsf-1.9'"), "{table}: only the retired branch moves");
        assert!(update.contains("AND url ~* first_party"), "{table}: only first-party rows move");
    }
    assert!(code.contains("begin_managed_owner_bootstrap") && code.contains("end_managed_owner_bootstrap"));

    // The SQL URL match agrees with the app's first-party check.
    let pattern = code.split("first_party CONSTANT TEXT := '").nth(1).unwrap().split("';").next().unwrap();
    let sql_match = regex::RegexBuilder::new(pattern).case_insensitive(true).build().unwrap();
    for url in [
        "https://github.com/nano-rs/parsers", "https://github.com/nano-rs/rules/", "github.com/nano-rs/rules.git",
        "https://www.github.com/NANO-RS/Parsers.git", "http://github.com/nano-rs/rules",
        "https://github.com/nano-rs/playbooks", "https://github.com/SigmaHQ/sigma", "https://example.com/nano-rs/parsers",
        "https://github.com/nano-rs/parsers/fork", "https://github.com/acme/nano-rs/rules",
    ] {
        assert_eq!(sql_match.is_match(url), nanosiem_core::schema::is_first_party_content_url(url), "{url}");
    }
}

/// The platform migration moves only the first-party seed rows.
#[cfg(feature = "enterprise")]
#[test]
fn platform_content_follows_main_migration_is_scoped() {
    let platform = include_str!("../../migrations/postgres-enterprise/9013780_platform_content_follows_main.sql");
    assert!(platform.contains("SET branch = 'main', checked_at = NULL"));
    assert!(platform.contains("WHERE branch = 'ocsf-1.9'"));
    assert!(platform.contains("(kind = 'parsers' AND url = 'https://github.com/nano-rs/parsers')"));
    assert!(platform.contains("(kind = 'rules' AND url = 'https://github.com/nano-rs/rules')"));
    assert!(!platform.contains("playbooks'"), "playbooks is never touched");
}

/// Whatever vector config the repository still carries never declares 1.8.
#[test]
fn bundled_vector_config_never_declares_ocsf18() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/vector");
    for directory in ["sources/parsers", "backup"] {
        let Ok(entries) = std::fs::read_dir(root.join(directory)) else { continue };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.extension().and_then(|v| v.to_str()) != Some("toml") {
                continue;
            }
            let content = std::fs::read_to_string(&path).unwrap();
            assert!(!content.contains("\"1.8.0\""), "{} carries OCSF 1.8", path.display());
        }
    }
    let seeded_otlp = include_str!("../../migrations/postgres/315_seed_otlp_log_ocsf_parser.sql");
    assert!(seeded_otlp.contains("\"version\": \"1.9.0\""));
    assert!(!seeded_otlp.contains("1.8.0"));
}

// =============================================================================
// Disposable local PostgreSQL: fresh install, upgrade, keep-current, offline.
// =============================================================================

mod pg {
    use super::*;
    use nanosiem_core::content_catalog_defaults::{ensure_first_party_catalogs, CatalogPlan};
    use nanosiem_core::db::dual_pool::{DualPool, DualPoolConfig};
    use nanosiem_core::parser_repository::ParserRepositoryService;
    use nanosiem_core::rule_repository::{GitHubClient, RuleRepositoryService};
    use sqlx::PgPool;
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const BRANCH: &str = "main";

    fn parser_yaml(path: &str, revision: &str) -> String {
        let slug = path.trim_start_matches("parsers-ocsf/").trim_end_matches("/parser.yaml").replace('/', "_");
        format!(
            "name: {slug}_ocsf\ndisplay_name: {slug} ({revision})\nversion: \"1.0.0\"\nocsf_version: \"1.9.0\"\n\
             description: synthetic fixture\nmatch_values:\n  - {slug}\ncategory: test\nvendor: test\nproduct: {slug}\n\
             parser_vrl: |\n  . = {{\"class_uid\": 0, \"metadata\": {{\"version\": \"1.9.0\"}}}}\n"
        )
    }

    fn rule_npl(path: &str, revision: &str) -> String {
        let slug = path.rsplit('/').next().unwrap().trim_end_matches(".yml").trim_end_matches(".yaml");
        format!(
            "---\ntitle: {slug}\ndescription: synthetic fixture {revision}\nauthor: nano.rs\nseverity: medium\nmode: live\n\
             detection_mode: scheduled\nschedule: \"*/10 * * * *\"\nlookback: 30m\n---\n\
             class_uid=1007 activity_id=1\n| where process.name=\"{slug}\"\n"
        )
    }

    /// Serve one catalog at `commit`; `revised` paths get revision "2".
    async fn serve(server: &MockServer, repo: &str, commit: &str, files: &[String], revised: &[&str]) {
        Mock::given(method("GET"))
            .and(path(format!("/repos/nano-rs/{repo}/branches/{BRANCH}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"name": BRANCH, "commit": {"sha": commit}})))
            .mount(server)
            .await;
        let tree: Vec<serde_json::Value> = files
            .iter()
            .map(|p| {
                let revision = if revised.contains(&p.as_str()) { "2" } else { "1" };
                serde_json::json!({"path": p, "type": "blob", "sha": format!("{p}@{revision}"), "size": 1, "url": null})
            })
            .collect();
        Mock::given(method("GET"))
            .and(path(format!("/repos/nano-rs/{repo}/git/trees/{BRANCH}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"sha": commit, "url": "", "tree": tree, "truncated": false})))
            .mount(server)
            .await;
        for p in files {
            let revision = if revised.contains(&p.as_str()) { "2" } else { "1" };
            let body = if repo == "parsers" { parser_yaml(p, revision) } else { rule_npl(p, revision) };
            // Parsers fetch raw content by commit, rules by branch.
            let reference = if repo == "parsers" { commit } else { BRANCH };
            Mock::given(method("GET"))
                .and(path(format!("/raw/nano-rs/{repo}/{reference}/{p}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .mount(server)
                .await;
        }
    }

    fn github(server: &MockServer) -> GitHubClient {
        GitHubClient::with_api_base_url(&server.uri()).with_raw_base_url(&format!("{}/raw", server.uri()))
    }

    async fn fresh_database() -> Option<(PgPool, String)> {
        let admin = std::env::var("TEST_CONTENT_DATABASE_URL").ok()?;
        let mut url = url::Url::parse(&admin).unwrap();
        assert!(matches!(url.host_str(), Some("localhost" | "127.0.0.1")), "local disposable database only");
        let name = format!("nan3758_{}", Uuid::new_v4().simple());
        let pool = PgPool::connect(&admin).await.unwrap();
        sqlx::raw_sql(&format!("CREATE DATABASE {name}")).execute(&pool).await.unwrap();
        pool.close().await;
        url.set_path(&format!("/{name}"));
        let pool = PgPool::connect(url.as_str()).await.unwrap();
        nanosiem_core::db::migrations::run_postgres_migrations(&pool).await.unwrap();
        Some((pool, url.to_string()))
    }

    async fn repo_row(pool: &PgPool, table: &str) -> (Uuid, String, bool, i32, Option<String>, Option<String>) {
        sqlx::query_as(&format!(
            "SELECT id, branch, auto_sync_enabled, sync_interval_hours, last_sync_status, last_sync_error FROM {table}"
        ))
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn rule_service(url: &str, server: &MockServer) -> RuleRepositoryService {
        let dual = DualPool::new_lake_control_plane(&DualPoolConfig { postgres_url: url.to_owned(), ..Default::default() })
            .await
            .unwrap();
        RuleRepositoryService::with_dual_pool(&dual).with_github_client(github(server))
    }

    /// Fresh install reaches the full catalog; an upstream change is applied
    /// on the next scheduled pass without overwriting a customised import.
    #[tokio::test]
    #[ignore = "requires TEST_CONTENT_DATABASE_URL (disposable localhost PostgreSQL)"]
    async fn fresh_install_follows_the_full_catalog_and_preserves_customisations() {
        let Some((pool, url)) = fresh_database().await else { return };
        let fixture = fixture();

        // First boot: both catalogs registered at main, hourly, auto-sync on.
        let outcomes = ensure_first_party_catalogs(&pool).await.unwrap();
        assert!(outcomes.iter().all(|o| matches!(o.plan, CatalogPlan::Create { .. })), "{outcomes:?}");
        for table in ["parser_repositories", "rule_repositories"] {
            let (_, branch, auto, hours, ..) = repo_row(&pool, table).await;
            assert_eq!((branch.as_str(), auto, hours), ("main", true, 1));
        }
        // Idempotent on every later start.
        let again = ensure_first_party_catalogs(&pool).await.unwrap();
        assert!(again.iter().all(|o| matches!(o.plan, CatalogPlan::Current(_))), "{again:?}");
        let due: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM parser_repositories WHERE auto_sync_enabled AND last_synced_at IS NULL) + \
                    (SELECT count(*) FROM rule_repositories WHERE auto_sync_enabled AND last_synced_at IS NULL)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(due, 2, "both catalogs are due on the first scheduler pass");

        let server = MockServer::start().await;
        let parser_paths = paths(&fixture, "parsers");
        let rule_paths = paths(&fixture, "rules");
        serve(&server, "parsers", "p1", &parser_paths, &[]).await;
        serve(&server, "rules", "r1", &rule_paths, &[]).await;

        let parsers = ParserRepositoryService::new(pool.clone()).with_github_client(github(&server));
        let rules = rule_service(&url, &server).await;
        let (parser_id, ..) = repo_row(&pool, "parser_repositories").await;
        let (rule_id, ..) = repo_row(&pool, "rule_repositories").await;
        let synced = parsers.sync_repository(parser_id).await.unwrap();
        assert_eq!(synced.parsers_total as usize, PARSERS);
        let synced = rules.sync_repository(rule_id).await.unwrap();
        assert_eq!(synced.rules_total as usize, RULES);
        let ocsf: i64 = sqlx::query_scalar("SELECT count(*) FROM repository_parsers WHERE raw_content LIKE '%ocsf_version: \"1.9.0\"%'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(ocsf as usize, PARSERS);

        // A customised import of one catalog rule.
        let target = rule_paths[0].clone();
        let repository_rule: Uuid = sqlx::query_scalar("SELECT id FROM repository_rules WHERE repository_id=$1 AND file_path=$2")
            .bind(rule_id)
            .bind(&target)
            .fetch_one(&pool)
            .await
            .unwrap();
        let detection: Uuid = sqlx::query_scalar(
            "INSERT INTO detection_rules (name, query, severity) VALUES ('customised', 'class_uid=1007 | where my_tuning=1', 'high') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO rule_imports (repository_rule_id, detection_rule_id, import_type, customizations) VALUES ($1,$2,'forked','{\"query\":true}')")
            .bind(repository_rule)
            .bind(detection)
            .execute(&pool)
            .await
            .unwrap();

        // Upstream revises the rule and a parser; the next scheduled pass applies it.
        server.reset().await;
        let revised_parser = parser_paths[0].clone();
        serve(&server, "parsers", "p2", &parser_paths, &[revised_parser.as_str()]).await;
        serve(&server, "rules", "r2", &rule_paths, &[target.as_str()]).await;
        let synced = parsers.sync_repository(parser_id).await.unwrap();
        assert_eq!((synced.parsers_updated, synced.parsers_total as usize), (1, PARSERS));
        let synced = rules.sync_repository(rule_id).await.unwrap();
        assert_eq!((synced.rules_updated, synced.rules_total as usize), (1, RULES));
        let catalog: String = sqlx::query_scalar("SELECT raw_content FROM repository_rules WHERE id=$1")
            .bind(repository_rule)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(catalog.contains("synthetic fixture 2"), "catalog row follows upstream");
        let (query, severity): (String, String) = sqlx::query_as("SELECT query, severity FROM detection_rules WHERE id=$1")
            .bind(detection)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!((query.as_str(), severity.as_str()), ("class_uid=1007 | where my_tuning=1", "high"), "customised rule untouched");
        let flagged: bool = sqlx::query_scalar("SELECT upstream_changed FROM rule_imports WHERE detection_rule_id=$1")
            .bind(detection)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(flagged, "the import is only flagged for review");
        let (_, _, _, _, status, _) = repo_row(&pool, "rule_repositories").await;
        assert_eq!(status.as_deref(), Some("success"));
        pool.close().await;
    }

    /// Upgrade: an install with the parser catalog on the retired `ocsf-1.9`
    /// default, auto-sync off and no rule catalog is moved to main, enabled and
    /// completed. A pinned branch and an operator-disabled catalog are left alone.
    #[tokio::test]
    #[ignore = "requires TEST_CONTENT_DATABASE_URL (disposable localhost PostgreSQL)"]
    async fn upgrade_moves_existing_catalogs_to_main() {
        let Some((pool, _)) = fresh_database().await else { return };
        // Explicit `ocsf-1.9`, as the NAN-3758 one-click / trigger default stored it.
        sqlx::query(
            "INSERT INTO parser_repositories (name, slug, url, branch, parsers_path, auto_sync_enabled, sync_interval_hours, last_synced_at) \
             VALUES ('nano-rs/parsers','nano-rs/parsers','https://github.com/nano-rs/parsers','ocsf-1.9','parsers/',FALSE,24,NOW() - interval '3 days')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let outcomes = ensure_first_party_catalogs(&pool).await.unwrap();
        assert!(matches!(&outcomes[0].plan, CatalogPlan::Update { branch: Some(b), enable_auto_sync: true, .. } if b == "main"));
        assert_eq!(outcomes[0].previous_branch.as_deref(), Some("ocsf-1.9"));
        assert!(matches!(outcomes[1].plan, CatalogPlan::Create { .. }));
        let (branch, auto, hours, last): (String, bool, i32, Option<chrono::DateTime<chrono::Utc>>) =
            sqlx::query_as("SELECT branch, auto_sync_enabled, sync_interval_hours, last_synced_at FROM parser_repositories")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((branch.as_str(), auto, hours, last), ("main", true, 24, None), "due now, operator cadence kept");

        // Pins and opt-outs survive the reconcile.
        sqlx::query("UPDATE parser_repositories SET branch='my-pin'").execute(&pool).await.unwrap();
        sqlx::query("UPDATE rule_repositories SET enabled=FALSE, branch='ocsf-1.9'").execute(&pool).await.unwrap();
        let outcomes = ensure_first_party_catalogs(&pool).await.unwrap();
        assert!(matches!(outcomes[0].plan, CatalogPlan::Current(_)));
        assert!(matches!(outcomes[1].plan, CatalogPlan::Disabled(_)));
        let branches: Vec<String> = sqlx::query_scalar("SELECT branch FROM parser_repositories UNION ALL SELECT branch FROM rule_repositories")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(branches, vec!["my-pin", "ocsf-1.9"]);

        // Migration 361's trigger, redefined by 367 (NAN-3897): omitted branches default to main.
        for (url, expected) in [("https://github.com/nano-rs/rules.git", "main"), ("https://github.com/SigmaHQ/sigma", "main")] {
            let stored: String = sqlx::query_scalar("INSERT INTO rule_repositories (name, slug, url) VALUES ($1,$1,$1) RETURNING branch")
                .bind(url)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(stored, expected, "{url}");
        }
        pool.close().await;
    }

    /// Offline: registration needs no network, a failed pull is recorded on
    /// the row for the repository pages and nothing panics.
    #[tokio::test]
    #[ignore = "requires TEST_CONTENT_DATABASE_URL (disposable localhost PostgreSQL)"]
    async fn offline_install_registers_and_reports_a_visible_failure() {
        let Some((pool, url)) = fresh_database().await else { return };
        ensure_first_party_catalogs(&pool).await.unwrap();
        // An unroutable endpoint: nothing listens on port 9 of localhost.
        let server = MockServer::start().await;
        let offline = GitHubClient::with_api_base_url("http://127.0.0.1:9").with_raw_base_url("http://127.0.0.1:9");
        let parsers = ParserRepositoryService::new(pool.clone()).with_github_client(offline.clone());
        let rules = rule_service(&url, &server).await.with_github_client(offline);
        let (parser_id, ..) = repo_row(&pool, "parser_repositories").await;
        let (rule_id, ..) = repo_row(&pool, "rule_repositories").await;
        assert!(parsers.sync_repository(parser_id).await.is_err());
        assert!(rules.sync_repository(rule_id).await.is_err());
        for table in ["parser_repositories", "rule_repositories"] {
            let (_, branch, auto, _, status, error) = repo_row(&pool, table).await;
            assert_eq!((branch.as_str(), auto, status.as_deref()), ("main", true, Some("failed")));
            assert!(error.is_some_and(|e| !e.is_empty()), "{table}: the failure reason is shown");
        }
        // Still due, so the next scheduler pass retries once the network is back.
        let due: i64 = sqlx::query_scalar("SELECT count(*) FROM rule_repositories WHERE last_synced_at IS NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(due, 1);
        pool.close().await;
    }
}
