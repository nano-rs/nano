// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pull-feed lane setup against a real Postgres (NAN-5903).
//!
//! A pull feed is refused until every lane it emits into has an enabled,
//! deployed HEC log source. `FeedLaneSetup` makes the missing ones from the
//! connector's catalog parser. These cover the cases that only show on a real
//! database: all lanes missing, some existing, all existing (idempotent), the
//! missing-parser refusal, the permission matrix, two submits racing, and a
//! deploy that fails half way.
//!
//! The deploy is faked (it flips `enabled`/`deployed`, or fails): the real
//! one renders Vector config and is covered by the deploy suites and the e2e
//! one-submit test. Every fixture uses its own parser name and lane prefix,
//! so the suite is safe to run in parallel and against a reused database.
//!
//! `#[ignore]`d DB suite: `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1
//! DATABASE_URL=postgres://... cargo test -p nanosiem-core --test
//! feed_lane_setup_integration -- --ignored`.

mod common;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use nanosiem_core::auth::{permissions, TargetEffect, TargetGrants};
use nanosiem_core::log_sources::feed_lane_setup::{
    owned_source_name, FeedConnector, FeedLaneSetup, LaneSetupError, LaneSourceAction, LaneSourceDeployer,
    LaneSourceOrigin, SetupLease,
};
use nanosiem_core::log_sources::{LogSourceRepository, NewLogSource};
use nanosiem_core::parser_repository::ParserRepositoryService;
use sqlx::PgPool;
use uuid::Uuid;

/// The first-party catalog row (setup only reads enabled first-party
/// repositories). Reused when the database already has one.
async fn catalog(pool: &PgPool) -> Uuid {
    // Tests run in parallel: insert-if-absent, then read whichever row won.
    sqlx::query(
        "INSERT INTO parser_repositories (name, slug, description, url, branch, parsers_path, auto_sync_enabled, sync_interval_hours) \
         VALUES ('nano parsers', 'nano-parsers', 'test', 'https://github.com/nano-rs/parsers', 'main', 'parsers-ocsf', false, 24) \
         ON CONFLICT DO NOTHING",
    )
    .execute(pool)
    .await
    .unwrap();
    let id: Uuid = sqlx::query_scalar(
        "SELECT id FROM parser_repositories WHERE lower(url) LIKE '%github.com/nano-rs/parsers%' ORDER BY created_at LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query("UPDATE parser_repositories SET enabled = true WHERE id = $1").bind(id).execute(pool).await.unwrap();
    id
}

/// A fixture connector: a catalog parser `<p>_ocsf` claiming `<p>_login`
/// and `<p>_admin`, like the Google Workspace parser claims four of its
/// seven usual lanes.
struct Fixture {
    pool: PgPool,
    prefix: String,
    parser: String,
}

impl Fixture {
    async fn new() -> Self {
        let pool = common::migrated_pool().await;
        let repo = catalog(&pool).await;
        let prefix = format!("t{}", &Uuid::new_v4().simple().to_string()[..10]);
        let parser = format!("{prefix}_ocsf");
        let yaml = format!(
            "name: {parser}\ndisplay_name: Fixture {prefix} (OCSF)\nmatch_values:\n  - {prefix}_login\n  - {prefix}_admin\n\
             parser_vrl: |\n  .metadata.log_source = \"{prefix}\"\nsamples:\n  - raw: \"{{}}\"\n"
        );
        sqlx::query(
            "INSERT INTO repository_parsers (repository_id, file_path, file_sha, raw_content, name, display_name, parser_vrl, kind) \
             VALUES ($1, $2, 'sha', $3, $4, $5, $6, 'parser')",
        )
        .bind(repo)
        .bind(format!("parsers-ocsf/{prefix}/parser.yaml"))
        .bind(&yaml)
        .bind(&parser)
        .bind(format!("Fixture {prefix} (OCSF)"))
        .bind(format!(".metadata.log_source = \"{prefix}\"\n"))
        .execute(&pool)
        .await
        .unwrap();
        Self { pool, prefix, parser }
    }

    fn lanes(&self, items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|i| format!("{}_{i}", self.prefix)).collect()
    }

    fn connector<'a>(&'a self, names: &'a [&'a str]) -> FeedConnector<'a> {
        FeedConnector { slug: &self.prefix, display: "Fixture", parsers: names }
    }

    /// The catalog import of the fixture parser, if any.
    async fn import_id(&self) -> Option<Uuid> {
        sqlx::query_scalar(
            "SELECT pi.log_source_id FROM parser_imports pi JOIN repository_parsers rp ON rp.id = pi.repository_parser_id \
             WHERE rp.name = $1",
        )
        .bind(&self.parser)
        .fetch_optional(&self.pool)
        .await
        .unwrap()
    }

    fn lane(&self, item: &str) -> String {
        format!("{}_{item}", self.prefix)
    }

    /// An operator's own enabled, deployed HEC source for `lane`.
    async fn hand_made_source(&self, lane: &str, deployed: bool) -> Uuid {
        let repo = LogSourceRepository::new(self.pool.clone());
        let s = repo
            .create(&NewLogSource {
                name: format!("hand {lane}"),
                description: None,
                namespace: "default".into(),
                timezone: "UTC".into(),
                source_type: "splunk_hec".into(),
                parser_vrl: ". = .".into(),
                output_fields: None,
                dispatch_source_config_id: None,
                category: None,
                vendor: None,
                product: None,
                icon: None,
                color: None,
                match_field: None,
                match_pattern: None,
                match_values: Some(vec![lane.to_string()]),
                sampling_ratio: None,
                sampling_exclude_condition: None,
                lifecycle_status: None,
            })
            .await
            .unwrap();
        sqlx::query("UPDATE log_sources SET enabled = true, deployed = $2 WHERE id = $1")
            .bind(s.id)
            .bind(deployed)
            .execute(&self.pool)
            .await
            .unwrap();
        s.id
    }

    /// Log sources whose match values touch this fixture's lanes.
    async fn sources(&self) -> Vec<(Uuid, String, Vec<String>, bool, bool)> {
        sqlx::query_as(
            "SELECT id, source_type, COALESCE(match_values, '{}'), enabled, deployed FROM log_sources \
             WHERE EXISTS (SELECT 1 FROM unnest(match_values) v WHERE v LIKE $1) ORDER BY created_at",
        )
        .bind(format!("{}_%", self.prefix))
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn cleanup(&self) {
        let _ = sqlx::query(
            "DELETE FROM log_sources WHERE EXISTS (SELECT 1 FROM unnest(match_values) v WHERE v LIKE $1)",
        )
        .bind(format!("{}_%", self.prefix))
        .execute(&self.pool)
        .await;
        let _ = sqlx::query("DELETE FROM log_sources WHERE name LIKE $1 OR name LIKE $2")
            .bind(format!("{}_pull%", self.prefix))
            .bind(format!("hand {}_%", self.prefix))
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("DELETE FROM repository_parsers WHERE name = $1").bind(&self.parser).execute(&self.pool).await;
    }
}

/// Deploy fake: turns the source on, or fails.
struct FakeDeployer {
    pool: PgPool,
    calls: AtomicUsize,
    fail: bool,
}

impl FakeDeployer {
    fn ok(pool: &PgPool) -> Self {
        Self { pool: pool.clone(), calls: AtomicUsize::new(0), fail: false }
    }
    fn failing(pool: &PgPool) -> Self {
        Self { pool: pool.clone(), calls: AtomicUsize::new(0), fail: true }
    }
}

#[async_trait::async_trait]
impl LaneSourceDeployer for FakeDeployer {
    async fn deploy(&self, id: Uuid) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err("the OCSF check failed on sample 1".into());
        }
        sqlx::query("UPDATE log_sources SET enabled = true, deployed = true, deployed_at = NOW(), first_deployed_at = COALESCE(first_deployed_at, NOW()) WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Everything a feed creator with the by-hand setup permissions holds.
const ALL: &[&str] = &[
    permissions::LOG_SOURCES_CREATE,
    permissions::LOG_SOURCES_EDIT,
    permissions::LOG_SOURCES_DEPLOY,
    permissions::PARSER_REPOSITORIES_IMPORT,
    permissions::SOURCE_CONFIGS_EDIT,
];

fn grants_for(perms: &[&str]) -> TargetGrants {
    TargetGrants::from_effects(TargetEffect::ALL.into_iter().filter(|e| perms.contains(&e.permission())))
}

async fn run(
    fx: &Fixture,
    lanes: &BTreeSet<String>,
    perms: &[&str],
    deployer: &FakeDeployer,
) -> (nanosiem_core::log_sources::feed_lane_setup::LaneSetupOutcome, Result<(), LaneSetupError>) {
    let parsers = ParserRepositoryService::new(fx.pool.clone());
    let setup = FeedLaneSetup::new(&fx.pool, &parsers);
    let owned: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
    let has = move |p: &str| owned.iter().any(|o| o == p);
    let names = [fx.parser.as_str()];
    let lease = SetupLease::acquire(&fx.pool, "test", std::time::Duration::from_secs(60)).await.expect("lease");
    let out = setup.set_up(&lease, fx.connector(&names), lanes, &has, &grants_for(perms), None, deployer).await;
    lease.release().await;
    out
}

#[tokio::test]
#[ignore]
async fn all_lanes_missing_creates_one_source_from_the_catalog_parser() {
    let fx = Fixture::new().await;
    let lanes = fx.lanes(&["login", "admin", "groups", "saml"]);
    let deployer = FakeDeployer::ok(&fx.pool);
    let (outcome, result) = run(&fx, &lanes, ALL, &deployer).await;
    result.expect("setup");
    let created: Vec<_> = outcome.created().collect();
    assert_eq!(created.len(), 1, "one parser, one source: {outcome:?}");
    assert_eq!(created[0].lanes, lanes.iter().cloned().collect::<Vec<_>>());
    assert_eq!(created[0].parser.as_deref(), Some(fx.parser.as_str()));
    assert_eq!(deployer.calls.load(Ordering::SeqCst), 1, "deployed once");
    let rows = fx.sources().await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (_, transport, values, enabled, deployed) = &rows[0];
    assert_eq!(transport, "splunk_hec");
    assert!(*enabled && *deployed);
    for lane in &lanes {
        assert!(values.contains(lane), "{lane} must route: {values:?}");
    }
    assert_eq!(values[0], fx.lane("login"), "the parser's own primary stays first");
    // Imported as a linked catalog parser, like the import UI does.
    let linked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM parser_imports WHERE log_source_id = $1)")
        .bind(rows[0].0)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert!(linked);
    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn existing_sources_are_reused_and_never_claimed_twice() {
    let fx = Fixture::new().await;
    let mine = fx.hand_made_source(&fx.lane("login"), true).await;
    let lanes = fx.lanes(&["login", "admin", "groups"]);
    let deployer = FakeDeployer::ok(&fx.pool);
    let (outcome, result) = run(&fx, &lanes, ALL, &deployer).await;
    result.expect("setup");
    let reused: Vec<_> = outcome.steps.iter().filter(|s| s.action == LaneSourceAction::Reuse).collect();
    assert_eq!(reused.len(), 1);
    assert_eq!(reused[0].log_source_id, Some(mine));
    assert_eq!(reused[0].lanes, vec![fx.lane("login")]);
    // The new source leaves out the lane the operator's source holds (it
    // would double-write), though the parser's YAML claims it.
    assert_eq!(outcome.withheld_values, vec![fx.lane("login")]);
    let rows = fx.sources().await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    let new = rows.iter().find(|r| r.0 != mine).unwrap();
    assert!(!new.2.contains(&fx.lane("login")), "{:?}", new.2);
    assert!(new.2.contains(&fx.lane("admin")) && new.2.contains(&fx.lane("groups")));
    let claimants = rows.iter().filter(|r| r.2.contains(&fx.lane("login"))).count();
    assert_eq!(claimants, 1, "exactly one source per lane");
    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn a_second_submit_is_idempotent() {
    let fx = Fixture::new().await;
    let lanes = fx.lanes(&["login", "admin", "token"]);
    let deployer = FakeDeployer::ok(&fx.pool);
    run(&fx, &lanes, ALL, &deployer).await.1.expect("first");
    let before = fx.sources().await;
    let (outcome, result) = run(&fx, &lanes, ALL, &deployer).await;
    result.expect("second");
    assert!(outcome.steps.iter().all(|s| s.action == LaneSourceAction::Reuse), "{outcome:?}");
    assert_eq!(deployer.calls.load(Ordering::SeqCst), 1, "nothing redeployed");
    assert_eq!(fx.sources().await, before, "nothing created or changed");

    // All existing: a creator with NO setup permission at all is not asked
    // for any.
    let (_, result) = run(&fx, &lanes, &[permissions::LOG_SOURCES_DEPLOY], &deployer).await;
    result.expect("nothing to set up needs no permission");

    // A new lane on a later feed widens the same source.
    let wider = fx.lanes(&["login", "admin", "token", "saml"]);
    let (outcome, result) = run(&fx, &wider, ALL, &deployer).await;
    result.expect("widen");
    let extend: Vec<_> = outcome.steps.iter().filter(|s| s.action == LaneSourceAction::Extend).collect();
    assert_eq!(extend.len(), 1);
    assert_eq!(extend[0].added_lanes, vec![fx.lane("saml")]);
    assert_eq!(fx.sources().await.len(), 1, "still one source");
    assert_eq!(deployer.calls.load(Ordering::SeqCst), 2, "redeployed for the new lane");
    fx.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn no_catalog_parser_is_refused_in_plain_english() {
    let fx = Fixture::new().await;
    let parsers = ParserRepositoryService::new(fx.pool.clone());
    let setup = FeedLaneSetup::new(&fx.pool, &parsers);
    let has = |_: &str| true;
    let deployer = FakeDeployer::ok(&fx.pool);
    let lanes = fx.lanes(&["login"]);
    let lease = SetupLease::acquire(&fx.pool, "test", std::time::Duration::from_secs(60)).await.unwrap();
    let (outcome, result) = setup
        .set_up(&lease, fx.connector(&["no_such_parser_ocsf"]), &lanes, &has, &TargetGrants::system(), None, &deployer)
        .await;
    let err = result.unwrap_err();
    assert!(matches!(err, LaneSetupError::ParserNotInCatalog { .. }), "{err:?}");
    let text = err.to_string();
    assert!(text.contains("could not find the Fixture parser (no_such_parser_ocsf)"), "{text}");
    assert!(text.contains(&format!("`{}`", fx.lane("login"))), "names the lane: {text}");
    assert!(outcome.steps.is_empty());
    assert!(fx.sources().await.is_empty(), "nothing written");
    // A connector with no parser at all.
    let (_, result) = setup.set_up(&lease, fx.connector(&[]), &lanes, &has, &TargetGrants::system(), None, &deployer).await;
    lease.release().await;
    assert!(matches!(result.unwrap_err(), LaneSetupError::NoParserForConnector { .. }));
    fx.cleanup().await;
}

/// The by-hand permissions, each one missing in turn, are refused before any
/// write, naming the permission.
#[tokio::test]
#[ignore]
async fn the_permission_matrix_matches_setting_up_by_hand() {
    let fx = Fixture::new().await;
    let lanes = fx.lanes(&["login", "admin"]);
    let deployer = FakeDeployer::ok(&fx.pool);
    // Can create feeds (log_sources:create + deploy) but cannot import
    // parsers: refused, nothing written.
    let feed_creator = [permissions::LOG_SOURCES_CREATE, permissions::LOG_SOURCES_DEPLOY];
    let (outcome, result) = run(&fx, &lanes, &feed_creator, &deployer).await;
    match result.unwrap_err() {
        // source_configs:edit too when a HEC source configuration exists for
        // the import to bind (as the by-hand import demands).
        LaneSetupError::NotPermitted { missing } => {
            assert_eq!(missing[0], permissions::PARSER_REPOSITORIES_IMPORT, "{missing:?}");
            assert!(missing[1..].iter().all(|p| *p == permissions::SOURCE_CONFIGS_EDIT), "{missing:?}");
        }
        other => panic!("{other:?}"),
    }
    assert!(outcome.created().next().is_none());
    assert!(fx.sources().await.is_empty(), "refused before any write");
    // Import without log_sources:create.
    let (_, result) =
        run(&fx, &lanes, &[permissions::PARSER_REPOSITORIES_IMPORT, permissions::LOG_SOURCES_DEPLOY], &deployer).await;
    match result.unwrap_err() {
        LaneSetupError::NotPermitted { missing } => assert!(missing.contains(&permissions::LOG_SOURCES_CREATE), "{missing:?}"),
        other => panic!("{other:?}"),
    }
    // Everything but deploy.
    let (_, result) = run(
        &fx,
        &lanes,
        &[permissions::PARSER_REPOSITORIES_IMPORT, permissions::LOG_SOURCES_CREATE, permissions::SOURCE_CONFIGS_EDIT],
        &deployer,
    )
    .await;
    match result.unwrap_err() {
        LaneSetupError::NotPermitted { missing } => assert_eq!(missing, vec![permissions::LOG_SOURCES_DEPLOY]),
        other => panic!("{other:?}"),
    }
    assert!(fx.sources().await.is_empty());
    assert_eq!(deployer.calls.load(Ordering::SeqCst), 0);

    // Widening an existing import needs log_sources:edit, as by hand.
    run(&fx, &lanes, ALL, &deployer).await.1.expect("set up by an admin");
    let wider = fx.lanes(&["login", "admin", "saml"]);
    let no_edit = [
        permissions::PARSER_REPOSITORIES_IMPORT,
        permissions::LOG_SOURCES_CREATE,
        permissions::LOG_SOURCES_DEPLOY,
    ];
    let (_, result) = run(&fx, &wider, &no_edit, &deployer).await;
    match result.unwrap_err() {
        LaneSetupError::NotPermitted { missing } => assert_eq!(missing, vec![permissions::LOG_SOURCES_EDIT]),
        other => panic!("{other:?}"),
    }
    let values = &fx.sources().await[0].2;
    assert!(!values.contains(&fx.lane("saml")), "not widened: {values:?}");
    fx.cleanup().await;
}

/// Two submits at once: one imports, the other waits for the lock and
/// reuses it. Never two sources, never a duplicate-import error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn racing_submits_create_one_source() {
    let fx = Arc::new(Fixture::new().await);
    let lanes = fx.lanes(&["login", "admin", "drive"]);
    let deployer = Arc::new(FakeDeployer::ok(&fx.pool));
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let (fx, lanes, deployer) = (fx.clone(), lanes.clone(), deployer.clone());
        tasks.push(tokio::spawn(async move { run(&fx, &lanes, ALL, &deployer).await }));
    }
    let mut created = 0;
    for t in tasks {
        let (outcome, result) = t.await.unwrap();
        result.expect("every submit succeeds");
        created += outcome.created().count();
    }
    assert_eq!(created, 1, "exactly one submit created the source");
    assert_eq!(fx.sources().await.len(), 1);
    fx.cleanup().await;
}

/// A deploy that fails half way leaves the created source (disabled, as a
/// failed first deploy leaves it), reports it so it is audited, and the next
/// submit reuses it instead of importing again.
#[tokio::test]
#[ignore]
async fn a_failed_deploy_leaves_a_reusable_source() {
    let fx = Fixture::new().await;
    let lanes = fx.lanes(&["login", "admin", "groups"]);
    let failing = FakeDeployer::failing(&fx.pool);
    let (outcome, result) = run(&fx, &lanes, ALL, &failing).await;
    let err = result.unwrap_err();
    assert!(matches!(err, LaneSetupError::DeployFailed { .. }), "{err:?}");
    assert!(err.to_string().contains("could not turn it on: the OCSF check failed on sample 1"), "{err}");
    assert!(err.to_string().contains("try again; nano reuses"), "{err}");
    let created: Vec<_> = outcome.created().collect();
    assert_eq!(created.len(), 1, "the created source is reported for the audit");
    let rows = fx.sources().await;
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].4, "not deployed");

    let ok = FakeDeployer::ok(&fx.pool);
    let (outcome, result) = run(&fx, &lanes, ALL, &ok).await;
    result.expect("retry");
    assert!(outcome.created().next().is_none(), "reused, not imported again: {outcome:?}");
    assert!(outcome.steps.iter().any(|s| s.action == LaneSourceAction::TurnOn));
    let rows = fx.sources().await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].3 && rows[0].4);
    fx.cleanup().await;
}

/// An enabled HEC source holding a lane without serving it (not deployed) is
/// named, not shadowed by a second claim.
#[tokio::test]
#[ignore]
async fn a_lane_held_by_an_undeployed_source_is_refused() {
    let fx = Fixture::new().await;
    fx.hand_made_source(&fx.lane("admin"), false).await;
    let deployer = FakeDeployer::ok(&fx.pool);
    let (_, result) = run(&fx, &fx.lanes(&["login", "admin"]), ALL, &deployer).await;
    let err = result.unwrap_err();
    assert!(err.is_conflict(), "{err:?}");
    assert!(err.to_string().contains(&format!("already takes {} events, but it is not deployed", fx.lane("admin"))), "{err}");
    assert_eq!(fx.sources().await.len(), 1, "nothing created");
    fx.cleanup().await;
}

/// A failed redeploy of a LIVE source takes the lanes it was widened with
/// back off: it stays `deployed`, so they would otherwise read as served
/// while Vector never learned them, and a retry would skip the deploy.
#[tokio::test]
#[ignore]
async fn a_failed_redeploy_takes_the_added_lanes_back() {
    let fx = Fixture::new().await;
    let ok = FakeDeployer::ok(&fx.pool);
    run(&fx, &fx.lanes(&["login", "admin"]), ALL, &ok).await.1.expect("set up");
    let failing = FakeDeployer::failing(&fx.pool);
    let (outcome, result) = run(&fx, &fx.lanes(&["login", "admin", "saml"]), ALL, &failing).await;
    assert!(matches!(result.unwrap_err(), LaneSetupError::DeployFailed { .. }));
    assert!(outcome.steps.iter().all(|s| s.action == LaneSourceAction::Reuse), "nothing to audit as changed: {outcome:?}");
    let rows = fx.sources().await;
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].2.contains(&fx.lane("saml")), "saml taken back: {:?}", rows[0].2);
    // The retry adds it again and deploys.
    let (outcome, result) = run(&fx, &fx.lanes(&["login", "admin", "saml"]), ALL, &ok).await;
    result.expect("retry");
    assert!(outcome.steps.iter().any(|s| s.action == LaneSourceAction::Extend));
    assert!(fx.sources().await[0].2.contains(&fx.lane("saml")));
    fx.cleanup().await;
}


/// Make the fixture's catalog import exist first (as an earlier setup or the
/// import UI would), then hand it to `tweak`.
async fn imported(fx: &Fixture, tweak: &'static str) -> Uuid {
    let ok = FakeDeployer::ok(&fx.pool);
    run(fx, &fx.lanes(&["login"]), ALL, &ok).await.1.expect("first setup");
    let id = fx.import_id().await.expect("imported");
    sqlx::query(tweak).bind(id).execute(&fx.pool).await.unwrap();
    id
}

/// P1-1: a customized catalog import (edited parser) is never changed: the
/// missing lanes go to a new connector-owned `<connector>_pull` source.
#[tokio::test]
#[ignore]
async fn a_customized_import_is_left_alone_and_a_pull_source_is_made() {
    let fx = Fixture::new().await;
    let import = imported(&fx, "UPDATE log_sources SET parser_vrl = parser_vrl || '\n.custom = true' WHERE id = $1").await;
    let before: Vec<String> = sqlx::query_scalar("SELECT unnest(match_values) FROM log_sources WHERE id = $1")
        .bind(import)
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    let ok = FakeDeployer::ok(&fx.pool);
    let (outcome, result) = run(&fx, &fx.lanes(&["login", "admin", "saml"]), ALL, &ok).await;
    result.expect("setup");
    let created: Vec<_> = outcome.created().collect();
    assert_eq!(created.len(), 1, "{outcome:?}");
    assert_eq!(created[0].log_source_name, owned_source_name(&fx.prefix, 1));
    assert_eq!(created[0].origin, Some(LaneSourceOrigin::PullSource));
    let after: Vec<String> = sqlx::query_scalar("SELECT unnest(match_values) FROM log_sources WHERE id = $1")
        .bind(import)
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    assert_eq!(before, after, "the customized import is not widened");
    // login stays with the (live) customized import; the pull source takes the rest.
    let owned: Vec<String> = sqlx::query_scalar("SELECT unnest(match_values) FROM log_sources WHERE name = $1")
        .bind(owned_source_name(&fx.prefix, 1))
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    assert!(!owned.contains(&fx.lane("login")), "{owned:?}");
    assert!(owned.contains(&fx.lane("saml")), "{owned:?}");
    fx.cleanup().await;
}

/// P1-1: an import the operator turned off after it went live stays off;
/// its retained match values do not block or collide with the pull source.
#[tokio::test]
#[ignore]
async fn a_turned_off_import_stays_off() {
    let fx = Fixture::new().await;
    let import = imported(&fx, "UPDATE log_sources SET enabled = false, deployed = false, deployed_at = NULL WHERE id = $1").await;
    let ok = FakeDeployer::ok(&fx.pool);
    let (outcome, result) = run(&fx, &fx.lanes(&["login", "admin"]), ALL, &ok).await;
    result.expect("setup");
    assert_eq!(outcome.created().next().map(|s| s.log_source_name.clone()), Some(owned_source_name(&fx.prefix, 1)));
    let enabled: bool = sqlx::query_scalar("SELECT enabled FROM log_sources WHERE id = $1").bind(import).fetch_one(&fx.pool).await.unwrap();
    assert!(!enabled, "the operator's turned-off import is not turned back on");
    // Every lane: exactly one ENABLED claimant (Vector's collision rule).
    for lane in fx.lanes(&["login", "admin"]) {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM log_sources WHERE enabled AND $1 = ANY(match_values)")
            .bind(&lane)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "{lane}");
    }
    fx.cleanup().await;
}

/// P1-1: claims match Vector's routing, including a source with no match
/// values, which Vector keys on the safe form of its name.
#[tokio::test]
#[ignore]
async fn an_implicit_name_claim_is_reused() {
    let fx = Fixture::new().await;
    let lane = fx.lane("login");
    // "TXX Login" routes as `txx_login` in Vector.
    let display = lane.replace('_', " ").to_uppercase();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO log_sources (id, name, namespace, timezone, source_type, parser_vrl, match_values, enabled, deployed, lifecycle_status, validated) \
         VALUES (gen_random_uuid(), $1, 'default', 'UTC', 'splunk_hec', '. = .', NULL, true, true, 'active', true) RETURNING id",
    )
    .bind(format!("hand {display}"))
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    // `hand TXX LOGIN` -> `hand_txx_login`: claim that exact key.
    let key = nanosiem_core::vector_naming::safe_name(&format!("hand {display}"));
    let ok = FakeDeployer::ok(&fx.pool);
    let parsers = ParserRepositoryService::new(fx.pool.clone());
    let setup = FeedLaneSetup::new(&fx.pool, &parsers);
    let names = [fx.parser.as_str()];
    let plan = setup.plan(fx.connector(&names), &[key.clone()].into_iter().collect()).await.unwrap();
    assert!(!plan.changes_anything(), "served by its implicit name: {:?}", plan.steps);
    assert_eq!(plan.steps[0].log_source_id, Some(id));
    let _ = ok;
    sqlx::query("DELETE FROM log_sources WHERE id = $1").bind(id).execute(&fx.pool).await.unwrap();
    fx.cleanup().await;
}

/// P1-3: what a plan needs depends on the plan: widening the clean import
/// takes log_sources:edit + deploy, never log_sources:create or import.
#[tokio::test]
#[ignore]
async fn required_permissions_follow_the_plan() {
    let fx = Fixture::new().await;
    let parsers = ParserRepositoryService::new(fx.pool.clone());
    let setup = FeedLaneSetup::new(&fx.pool, &parsers);
    let names = [fx.parser.as_str()];
    let fresh = setup.plan(fx.connector(&names), &fx.lanes(&["login"])).await.unwrap();
    assert!(fresh.required_permissions.contains(&permissions::PARSER_REPOSITORIES_IMPORT));
    let ok = FakeDeployer::ok(&fx.pool);
    run(&fx, &fx.lanes(&["login"]), ALL, &ok).await.1.expect("first");
    let wider = setup.plan(fx.connector(&names), &fx.lanes(&["login", "saml"])).await.unwrap();
    assert_eq!(wider.required_permissions, vec![permissions::LOG_SOURCES_EDIT, permissions::LOG_SOURCES_DEPLOY]);
    // An edit + deploy role can carry it out.
    let editor = [permissions::LOG_SOURCES_EDIT, permissions::LOG_SOURCES_DEPLOY];
    run(&fx, &fx.lanes(&["login", "saml"]), &editor, &ok).await.1.expect("edit + deploy widens");
    fx.cleanup().await;
}

/// P1-1: a never-live import (a failed first setup) turning on gives up the
/// values another enabled HEC source took meanwhile, so it cannot collide.
#[tokio::test]
#[ignore]
async fn a_never_live_import_gives_up_contested_values() {
    let fx = Fixture::new().await;
    let failing = FakeDeployer::failing(&fx.pool);
    let _ = run(&fx, &fx.lanes(&["login", "admin"]), ALL, &failing).await;
    let import = fx.import_id().await.expect("imported");
    let mine = fx.hand_made_source(&fx.lane("login"), true).await;
    let ok = FakeDeployer::ok(&fx.pool);
    let (outcome, result) = run(&fx, &fx.lanes(&["login", "admin"]), ALL, &ok).await;
    result.expect("setup");
    assert_eq!(outcome.withheld_values, vec![fx.lane("login")]);
    let values: Vec<String> = sqlx::query_scalar("SELECT unnest(match_values) FROM log_sources WHERE id = $1")
        .bind(import)
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    assert!(!values.contains(&fx.lane("login")), "{values:?}");
    let _ = mine;
    fx.cleanup().await;
}


/// R2 P1-1: the lease serializes starts without holding a connection: a
/// second claim waits, then is Busy; a released lease is free at once; an
/// expired one is taken over.
#[tokio::test]
#[ignore]
async fn the_setup_lease_serializes_and_lapses() {
    let pool = common::migrated_pool().await;
    // Serial with the other suites' leases: wait for any to finish first.
    let first = SetupLease::acquire(&pool, "first", std::time::Duration::from_secs(120)).await.unwrap();
    let busy = SetupLease::acquire(&pool, "second", std::time::Duration::from_millis(600)).await;
    assert!(matches!(busy, Err(LaneSetupError::Busy)), "a held lease is Busy for others");
    first.release().await;
    let second = SetupLease::acquire(&pool, "second", std::time::Duration::from_secs(60)).await.expect("free after release");
    // A holder that died: its row lapses and is taken over. (Only our own
    // lease row exists while we hold it; other tests in this binary wait.)
    sqlx::query("UPDATE connector_feed_setup_leases SET expires_at = now() - interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    let third = SetupLease::acquire(&pool, "third", std::time::Duration::from_secs(60)).await.expect("expired lease taken over");
    // The lapsed holder's release does not free the new holder's lease.
    second.release().await;
    let still = SetupLease::acquire(&pool, "fourth", std::time::Duration::from_millis(600)).await;
    assert!(matches!(still, Err(LaneSetupError::Busy)), "an old owner cannot release a taken-over lease");
    // Dropped without release: released in the background.
    drop(third);
    let fifth = SetupLease::acquire(&pool, "fifth", std::time::Duration::from_secs(60)).await.expect("released on drop");
    fifth.release().await;
}

/// R2 P1-2: a pull source that is no longer pristine (turned off after it
/// was live) is never changed; the next free name gets a new one.
#[tokio::test]
#[ignore]
async fn a_customized_pull_source_is_left_alone() {
    let fx = Fixture::new().await;
    imported(&fx, "UPDATE log_sources SET parser_vrl = parser_vrl || '\n.custom = true' WHERE id = $1").await;
    let ok = FakeDeployer::ok(&fx.pool);
    run(&fx, &fx.lanes(&["login", "saml"]), ALL, &ok).await.1.expect("pull source made");
    let pull = owned_source_name(&fx.prefix, 1);
    sqlx::query("UPDATE log_sources SET enabled = false, deployed = false, deployed_at = NULL WHERE name = $1")
        .bind(&pull)
        .execute(&fx.pool)
        .await
        .unwrap();
    let (outcome, result) = run(&fx, &fx.lanes(&["login", "saml", "groups"]), ALL, &ok).await;
    result.expect("setup");
    let created: Vec<_> = outcome.created().collect();
    assert_eq!(created.len(), 1, "{outcome:?}");
    assert_eq!(created[0].log_source_name, owned_source_name(&fx.prefix, 2));
    let (enabled, values): (bool, Vec<String>) =
        sqlx::query_as("SELECT enabled, match_values FROM log_sources WHERE name = $1").bind(&pull).fetch_one(&fx.pool).await.unwrap();
    assert!(!enabled, "the turned-off pull source stays off");
    assert!(!values.contains(&fx.lane("groups")), "and is not widened: {values:?}");
    fx.cleanup().await;
}

/// R2 P1-2: a name taken in Vector's identifier space (another source whose
/// safe name is `<connector>_pull`) is skipped, never a unique-index 500.
#[tokio::test]
#[ignore]
async fn a_taken_pull_name_moves_to_the_next() {
    let fx = Fixture::new().await;
    imported(&fx, "UPDATE log_sources SET parser_vrl = parser_vrl || '\n.custom = true' WHERE id = $1").await;
    // "TXX Pull" generates the identifier `txx_pull`.
    let clash = format!("{} Pull", fx.prefix.to_uppercase());
    sqlx::query(
        "INSERT INTO log_sources (id, name, namespace, timezone, source_type, parser_vrl, match_values, lifecycle_status, validated) \
         VALUES (gen_random_uuid(), $1, 'default', 'UTC', 'routed', '. = .', ARRAY['unrelated_x'], 'active', true)",
    )
    .bind(&clash)
    .execute(&fx.pool)
    .await
    .unwrap();
    let ok = FakeDeployer::ok(&fx.pool);
    let (outcome, result) = run(&fx, &fx.lanes(&["login", "saml"]), ALL, &ok).await;
    result.expect("setup");
    assert_eq!(outcome.created().next().map(|s| s.log_source_name.clone()), Some(owned_source_name(&fx.prefix, 2)));
    sqlx::query("DELETE FROM log_sources WHERE name = $1").bind(&clash).execute(&fx.pool).await.unwrap();
    fx.cleanup().await;
}

/// R2 P2-2: an import whose PUBLISHED version is customized is not pristine,
/// though its working copy was put back to the catalog parser.
#[tokio::test]
#[ignore]
async fn a_customized_published_version_is_not_pristine() {
    let fx = Fixture::new().await;
    let ok = FakeDeployer::ok(&fx.pool);
    run(&fx, &fx.lanes(&["login"]), ALL, &ok).await.1.expect("first");
    let import = fx.import_id().await.unwrap();
    sqlx::query(
        "INSERT INTO log_source_versions (log_source_id, version_number, parser_vrl, is_active, change_reason) \
         VALUES ($1, 1, '.custom = true', TRUE, 'test')",
    )
    .bind(import)
    .execute(&fx.pool)
    .await
    .unwrap();
    let (outcome, result) = run(&fx, &fx.lanes(&["login", "saml"]), ALL, &ok).await;
    result.expect("setup");
    let made = outcome.created().next().expect("a pull source");
    assert_eq!(made.origin, Some(LaneSourceOrigin::PullSource));
    let values: Vec<String> =
        sqlx::query_scalar("SELECT unnest(match_values) FROM log_sources WHERE id = $1").bind(import).fetch_all(&fx.pool).await.unwrap();
    assert!(!values.contains(&fx.lane("saml")), "the customized import is not widened");
    sqlx::query("DELETE FROM log_source_versions WHERE log_source_id = $1").bind(import).execute(&fx.pool).await.unwrap();
    fx.cleanup().await;
}


/// R3 P1-2: an operator's Undeploy (which disables the source and clears
/// `deployed_at`) is not mistaken for "never live": the import is left off
/// and a pull source takes the lanes.
#[tokio::test]
#[ignore]
async fn an_undeployed_import_is_not_turned_back_on() {
    let fx = Fixture::new().await;
    let ok = FakeDeployer::ok(&fx.pool);
    run(&fx, &fx.lanes(&["login"]), ALL, &ok).await.1.expect("first setup");
    let import = fx.import_id().await.unwrap();
    let repo = LogSourceRepository::new(fx.pool.clone());
    repo.disable(import).await.unwrap();
    repo.mark_undeployed(import).await.unwrap();
    let (outcome, result) = run(&fx, &fx.lanes(&["login", "admin"]), ALL, &ok).await;
    result.expect("setup");
    assert_eq!(outcome.created().next().map(|s| s.log_source_name.clone()), Some(owned_source_name(&fx.prefix, 1)));
    let enabled: bool = sqlx::query_scalar("SELECT enabled FROM log_sources WHERE id = $1").bind(import).fetch_one(&fx.pool).await.unwrap();
    assert!(!enabled, "the undeployed import stays off");
    fx.cleanup().await;
}

/// R3 P2-1: a holder whose lease lapsed and was taken over is fenced: it
/// changes nothing (LeaseLost), and the new holder is unaffected.
#[tokio::test]
#[ignore]
async fn a_lapsed_lease_is_fenced() {
    let fx = Fixture::new().await;
    let parsers = ParserRepositoryService::new(fx.pool.clone());
    let setup = FeedLaneSetup::new(&fx.pool, &parsers);
    let names = [fx.parser.as_str()];
    let ok = FakeDeployer::ok(&fx.pool);
    let stale = SetupLease::acquire(&fx.pool, "stale", std::time::Duration::from_secs(120)).await.unwrap();
    // It stalls past its lease; another start takes over.
    sqlx::query("UPDATE connector_feed_setup_leases SET expires_at = now() - interval '1 second'")
        .execute(&fx.pool)
        .await
        .unwrap();
    let fresh = SetupLease::acquire(&fx.pool, "fresh", std::time::Duration::from_secs(60)).await.expect("taken over");
    assert!(matches!(stale.ensure_held().await, Err(LaneSetupError::LeaseLost)));
    let has = |_: &str| true;
    let (outcome, result) = setup
        .set_up(&stale, fx.connector(&names), &fx.lanes(&["login"]), &has, &TargetGrants::system(), None, &ok)
        .await;
    assert!(matches!(result, Err(LaneSetupError::LeaseLost)), "{result:?}");
    assert!(outcome.created().next().is_none());
    assert!(fx.sources().await.is_empty(), "a fenced holder writes nothing");
    assert_eq!(ok.calls.load(Ordering::SeqCst), 0, "and deploys nothing");
    fresh.ensure_held().await.expect("the new holder still holds it");
    drop(stale);
    fresh.release().await;
    fx.cleanup().await;
}
