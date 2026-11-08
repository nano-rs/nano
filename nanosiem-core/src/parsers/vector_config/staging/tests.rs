// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2296 — promotion mirrors the staged tree instead of overlaying it.
//! NAN-2305 — the candidate tree covers every directory Vector loads, staging
//! splits enrichment parsers out of the logs pipeline, and mirroring only
//! deletes files this subsystem generated.

use super::*;
use tempfile::TempDir;

/// Route names the staged `_router.toml` emits under `source_router`.
///
/// Deliberately local to this test module. These were briefly borrowed from
/// `backup.rs`, which broke the test build the moment NAN-2302 replaced that
/// module's narrow gate with a full component-graph check — two PRs that were
/// each green against their own base. A staging test asserting a staging
/// invariant should not reach into the backup module's internals.
fn staged_router_routes(router_toml: &str) -> std::collections::HashSet<String> {
    toml::from_str::<toml::Value>(router_toml)
        .ok()
        .and_then(|value| {
            value
                .get("transforms")?
                .get("source_router")?
                .get("route")?
                .as_table()
                .map(|table| table.keys().cloned().collect())
        })
        .unwrap_or_default()
}

/// `source_router.<name>` inputs declared by any transform in a parser TOML.
fn staged_source_router_inputs(parser_toml: &str) -> Vec<String> {
    let Ok(value) = toml::from_str::<toml::Value>(parser_toml) else {
        return Vec::new();
    };
    let Some(transforms) = value.get("transforms").and_then(|t| t.as_table()) else {
        return Vec::new();
    };
    transforms
        .values()
        .filter_map(|component| component.get("inputs")?.as_array())
        .flatten()
        .filter_map(|input| input.as_str())
        .filter_map(|input| input.strip_prefix("source_router."))
        .filter(|route| !route.is_empty())
        .map(str::to_string)
        .collect()
}

/// Lay out a config dir with a COMPLETED staged parsers tree (marker included,
/// as `stage_parsers` writes it) and return the manager.
async fn staged_manager(
    staged: &[(&str, &str)],
    active: &[(&str, &str)],
) -> (TempDir, VectorConfigManager) {
    let (tmp, manager) = staged_manager_raw(staged, active).await;
    mark_staging_complete(&manager).await;
    (tmp, manager)
}

/// Same, without the completion marker — an interrupted stage.
async fn staged_manager_raw(
    staged: &[(&str, &str)],
    active: &[(&str, &str)],
) -> (TempDir, VectorConfigManager) {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    write_staging_tree(&manager, staged).await;

    fs::create_dir_all(&manager.parsers_dir).await.expect("active");
    for (name, body) in active {
        fs::write(manager.parsers_dir.join(name), body).await.expect("write active");
    }

    (tmp, manager)
}

/// (Re)populate the staged parsers tree of an existing manager, so a test can
/// run more than one promotion against the same active directory.
async fn write_staging_tree(manager: &VectorConfigManager, staged: &[(&str, &str)]) {
    let staged_parsers = manager.staged_parsers_dir();
    fs::create_dir_all(&staged_parsers).await.expect("staging");
    for (name, body) in staged {
        fs::write(staged_parsers.join(name), body).await.expect("write staged");
    }
}

async fn mark_staging_complete(manager: &VectorConfigManager) {
    fs::write(manager.staging_dir().join(STAGING_COMPLETE_MARKER), "staged\n")
        .await
        .expect("marker");
}

/// Every quarantined file name under the config root, across all batches.
async fn quarantined_names(manager: &VectorConfigManager) -> Vec<String> {
    let root = manager.quarantine_dir();
    let mut found = Vec::new();
    let Ok(mut batches) = fs::read_dir(&root).await else {
        return found;
    };
    while let Some(batch) = batches.next_entry().await.expect("batch") {
        let mut files = fs::read_dir(batch.path()).await.expect("batch dir");
        while let Some(file) = files.next_entry().await.expect("file") {
            found.push(file.file_name().to_string_lossy().to_string());
        }
    }
    found.sort();
    found
}

/// A minimal `Parser`. `kind`/`source_type` are the two axes every test below
/// varies; everything else is inert.
fn test_parser(name: &str, kind: &str, source_type: &str) -> Parser {
    Parser {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        source_type: source_type.to_string(),
        parser_vrl: ". = .".to_string(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        enabled: true,
        validated: true,
        validation_error: None,
        category: None,
        vendor: None,
        product: None,
        kind: kind.to_string(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        namespace: "default".to_string(),
        timezone: "UTC".to_string(),
        match_values: None,
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// An enrichment parser shaped like the real ones: `kind = "enrichment"`,
/// `source_type = "nano_enrich"`, and an unrecognised `enrich_kind` so the lane
/// guard only checks that the normalize VRL compiles and runs.
fn enrichment_parser(name: &str) -> Parser {
    let mut p = test_parser(name, "enrichment", "nano_enrich");
    p.parser_vrl = String::new();
    p.enrich_kind = Some("custom_contract".to_string());
    p.enrich_source = Some("testsrc".to_string());
    p.target_table = Some("user_registry".to_string());
    p.normalize_vrl = Some(". = { \"external_id\": to_string(.id) ?? \"\" }".to_string());
    p
}

/// The bug: a rename regenerates `_router.toml` without the old route and
/// writes a new parser file, but the OLD file stayed in the active directory
/// pointing at `source_router.<old_name>`. Vector treats an input naming a
/// missing component as fatal to the entire config, so every reload after a
/// rename was rejected and the pre-rename config kept running — while deploy
/// and publish reported success, because the reload is best-effort.
#[tokio::test]
async fn promotion_removes_the_pre_rename_parser_file() {
    let (_tmp, manager) = staged_manager(
        &[
            ("github_public_events.toml", "inputs = [\"source_router.github_public_events\"]"),
            ("_router.toml", "github_public_events = '.source_type == \"github_public_events\"'"),
        ],
        &[
            // What the rename left behind.
            (
                "github_public_events__raw_collector_.toml",
                "inputs = [\"source_router.github_public_events__raw_collector_\"]",
            ),
        ],
    )
    .await;

    manager.promote_staged().await.expect("promote");

    let orphan = manager
        .parsers_dir
        .join("github_public_events__raw_collector_.toml");
    assert!(
        !orphan.exists(),
        "pre-rename parser file survived promotion — it references a router output \
         that no longer exists, which makes the whole Vector config unloadable"
    );
    assert!(manager.parsers_dir.join("github_public_events.toml").exists());
    assert!(manager.parsers_dir.join("_router.toml").exists());
}

/// Shared infrastructure survives because `stage_parsers` always emits it, not
/// because of a name-prefix exemption. Modelled the way a real deploy stages:
/// the infra files are present in BOTH trees.
#[tokio::test]
async fn promotion_keeps_staged_infrastructure_and_ignores_dotfiles() {
    let (_tmp, manager) = staged_manager(
        &[
            ("apache.toml", "inputs = [\"source_router.apache\"]"),
            ("_router.toml", "shared"),
            ("_combiner.toml", "shared"),
            ("_pipeline.toml", "shared"),
            ("_enrichment.toml", "shared"),
        ],
        &[
            ("_router.toml", "stale"),
            ("_combiner.toml", "stale"),
            ("_pipeline.toml", "stale"),
            ("_enrichment.toml", "stale"),
            (".gitkeep", ""),
        ],
    )
    .await;

    manager.promote_staged().await.expect("promote");

    for infra in ["_router", "_combiner", "_pipeline", "_enrichment"] {
        let path = manager.parsers_dir.join(format!("{infra}.toml"));
        assert!(path.exists(), "{infra} was pruned");
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "shared");
    }
    assert!(manager.parsers_dir.join(".gitkeep").exists());
    assert!(manager.parsers_dir.join("apache.toml").exists());
}

/// `safe_name` maps every non-alphanumeric character to `_`, so a source named
/// "(Legacy) Apache" generates `_legacy__apache.toml`. Skipping `_`-prefixed
/// files during pruning would strand that on rename and reproduce the very bug
/// this change fixes — an underscore prefix does not mean "infrastructure".
#[tokio::test]
async fn promotion_removes_an_underscore_prefixed_parser_orphan() {
    let (_tmp, manager) = staged_manager(
        &[
            ("legacy_apache.toml", "inputs = [\"source_router.legacy_apache\"]"),
            ("_router.toml", "shared"),
        ],
        &[
            // safe_name("(Legacy) Apache")
            ("_legacy__apache.toml", "inputs = [\"source_router._legacy__apache\"]"),
        ],
    )
    .await;

    manager.promote_staged().await.expect("promote");

    assert!(
        !manager.parsers_dir.join("_legacy__apache.toml").exists(),
        "an underscore-prefixed PARSER file survived promotion — same fatal \
         dangling-input config as the plain rename case"
    );
    assert!(manager.parsers_dir.join("legacy_apache.toml").exists());
    assert!(manager.parsers_dir.join("_router.toml").exists());
}

/// A genuine zero-parser deploy is NOT an empty staging tree — `stage_parsers`
/// still writes the infrastructure files. It must promote those and remove every
/// per-parser TOML, rather than being mistaken for the corrupt-staging case.
#[tokio::test]
async fn zero_parser_stage_promotes_infrastructure_and_clears_parsers() {
    let (_tmp, manager) = staged_manager(
        &[("_router.toml", "shared"), ("_combiner.toml", "shared")],
        &[
            ("apache.toml", "inputs = [\"source_router.apache\"]"),
            ("sysmon.toml", "inputs = [\"source_router.sysmon\"]"),
        ],
    )
    .await;

    manager.promote_staged().await.expect("promote");

    assert!(!manager.parsers_dir.join("apache.toml").exists());
    assert!(!manager.parsers_dir.join("sysmon.toml").exists());
    assert!(manager.parsers_dir.join("_router.toml").exists());
}

/// NAN-2297: serialization comes from services sharing ONE manager instance,
/// not from each holding a lock of its own. `LogSourceService` used to build its
/// own `VectorConfigManager` while staging into the same directory as
/// `ParserService` — two mutexes, zero mutual exclusion. This pins both halves:
/// the guard is exclusive per manager, and separate managers do not serialize,
/// which is precisely why the production wiring hands the same `Arc` around.
#[tokio::test]
async fn deploy_guard_is_exclusive_per_manager_instance() {
    let tmp_a = TempDir::new().expect("tempdir");
    let tmp_b = TempDir::new().expect("tempdir");
    let a = VectorConfigManager::new(tmp_a.path());
    let b = VectorConfigManager::new(tmp_b.path());

    let guard = a.lock_deploys().await;

    // Same instance: a second acquisition must wait.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), a.lock_deploys())
            .await
            .is_err(),
        "deploy guard let a second holder in on the same manager"
    );

    // Separate instance: no serialization — the bug NAN-2297 fixes by wiring.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), b.lock_deploys())
            .await
            .is_ok(),
        "expected independent managers to have independent locks"
    );

    drop(guard);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), a.lock_deploys())
            .await
            .is_ok(),
        "guard did not release"
    );
}

/// NAN-2298: an interrupted stage must fail loudly. Before the marker, a
/// staging tree that existed but was never finished promoted as a SUCCESS —
/// nothing copied, staging cleaned up, `Ok(())` returned, and the caller
/// recording a successful deployment over a config that never changed.
#[tokio::test]
async fn incomplete_staging_is_rejected_and_preserves_the_active_config() {
    let (_tmp, manager) = staged_manager_raw(
        // Half-written: one parser landed, the stage died before the marker.
        &[("apache.toml", "inputs = [\"source_router.apache\"]")],
        &[
            ("apache.toml", "live"),
            ("sysmon.toml", "inputs = [\"source_router.sysmon\"]"),
        ],
    )
    .await;

    let err = manager
        .promote_staged()
        .await
        .expect_err("an unfinished stage must not promote");
    assert!(
        format!("{err}").contains("incomplete"),
        "unexpected error: {err}"
    );

    // Nothing on the active side was touched — in particular sysmon.toml, which
    // the partial tree would otherwise have pruned.
    assert_eq!(
        fs::read_to_string(manager.parsers_dir.join("apache.toml"))
            .await
            .unwrap(),
        "live"
    );
    assert!(manager.parsers_dir.join("sysmon.toml").exists());
}

/// NAN-2300: pins the backup/restore SEMANTICS the fixed sequence relies on —
/// restore after backup-then-promote returns the previous config, not the new
/// one.
///
/// Honest scope: this does not guard the production ordering. It calls
/// `backup_current`/`promote_staged`/`restore_backup` directly, none of which
/// changed in NAN-2300, so moving the backup back to the wrong side of
/// promotion inside `deploy_parser` would NOT fail this test. Guarding that
/// needs injectable reload/health seams so `deploy_parser` is testable without
/// a live Vector — filed rather than faked here, because a test that looks like
/// it covers the regression and doesn't is worse than none.
#[tokio::test]
async fn backup_before_promote_restores_the_previous_config() {
    let (_tmp, manager) = staged_manager(
        &[("apache.toml", "NEW"), ("_router.toml", "NEW ROUTER")],
        &[("apache.toml", "OLD"), ("_router.toml", "OLD ROUTER")],
    )
    .await;

    let generation = manager.backup_current().await.expect("backup");
    manager.promote_staged().await.expect("promote");

    // Promotion published the staged tree.
    assert_eq!(
        fs::read_to_string(manager.parsers_dir.join("apache.toml"))
            .await
            .unwrap(),
        "NEW"
    );

    // Rollback returns what was live before it, which is the whole point.
    manager.restore_backup(&generation).await.expect("restore");
    assert_eq!(
        fs::read_to_string(manager.parsers_dir.join("apache.toml"))
            .await
            .unwrap(),
        "OLD",
        "rollback restored the promoted config instead of the previous one — \
         the backup was taken on the wrong side of promotion"
    );
}

/// NAN-2298: the collision check in `stage_parsers` returns BEFORE
/// `cleanup_staging`, so a previously completed stage would otherwise keep its
/// marker and tree — and a later promotion would accept that stale stage as if
/// it were the current one, publishing config the caller never staged. The
/// marker is therefore invalidated as the first thing `stage_parsers` does.
#[tokio::test]
async fn a_failed_stage_invalidates_the_previous_completion_marker() {
    let (_tmp, manager) = staged_manager(
        &[("apache.toml", "inputs = [\"source_router.apache\"]")],
        &[],
    )
    .await;
    assert!(manager.staging_dir().join(STAGING_COMPLETE_MARKER).exists());

    // Two enabled parsers claiming one source_type — rejected before cleanup.
    let collide = |name: &str| {
        let mut p = test_parser(name, "log", "routed");
        p.match_values = Some(vec!["sysmon".to_string()]);
        p
    };
    let err = manager
        .stage_parsers(&[collide("Sysmon A"), collide("Sysmon B")])
        .await
        .expect_err("colliding claims must fail staging");
    assert!(format!("{err}").to_lowercase().contains("sysmon"));

    assert!(
        !manager.staging_dir().join(STAGING_COMPLETE_MARKER).exists(),
        "a failed stage left the previous completion marker in place"
    );
    manager
        .promote_staged()
        .await
        .expect_err("the leftover tree must not promote as if it were current");
}

/// A staging tree with NO files at all is corruption or an upstream failure —
/// distinct from the zero-parser deploy above, which still carries
/// infrastructure. Mirroring it would delete every active parser and take
/// ingestion down, so promotion must leave the active config alone rather than
/// "successfully" emptying it.
#[tokio::test]
async fn file_less_staging_does_not_wipe_the_active_parsers() {
    let (_tmp, manager) = staged_manager(
        &[],
        &[("apache.toml", "inputs = [\"source_router.apache\"]")],
    )
    .await;

    manager.promote_staged().await.expect("promote");

    assert!(
        manager.parsers_dir.join("apache.toml").exists(),
        "an empty staging tree emptied the active parser directory"
    );
}

// ---------------------------------------------------------------------------
// NAN-2305 Finding A — the candidate tree covers every directory Vector loads
// ---------------------------------------------------------------------------

/// The bug: `stage_parsers` writes a `_router.toml` whose `source_router.inputs`
/// names every deployed source config's `<stem>_route` transform, but those
/// transforms are declared in `sources/configs` — a directory the candidate tree
/// never contained. Vector treats an input naming a component it cannot see as
/// fatal to the WHOLE config, so `vector validate` failed and every parser
/// deploy for a tenant running a pull source was refused, indefinitely, for a
/// config that was in fact correct.
#[tokio::test]
async fn staging_carries_the_source_configs_its_router_depends_on() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    let configs = tmp.path().join("sources").join("configs");
    fs::create_dir_all(&configs).await.expect("configs");
    let kafka = "[transforms.prod_kafka_route]\n\
                 type = \"remap\"\n\
                 inputs = [\"prod_kafka_source\"]\n\
                 source = '.source_type = \"prod_kafka\"'\n";
    fs::write(configs.join("prod_kafka.toml"), kafka)
        .await
        .expect("kafka");

    manager.stage_parsers(&[]).await.expect("stage");

    let router = fs::read_to_string(manager.staged_parsers_dir().join("_router.toml"))
        .await
        .expect("router");
    assert!(
        router.contains("prod_kafka_route"),
        "precondition: the staged router must wire the deployed source config's route"
    );

    let staged_config = manager
        .staging_dir()
        .join("sources")
        .join("configs")
        .join("prod_kafka.toml");
    assert!(
        staged_config.exists(),
        "the staged tree omits sources/configs, so `vector validate` cannot see the \
         prod_kafka_route transform the staged router names — validation fails and every \
         parser deploy for this tenant is refused"
    );
    assert_eq!(
        fs::read_to_string(&staged_config).await.unwrap(),
        kafka,
        "the staged copy must be the config Vector actually loads"
    );
}

/// `--config-dir` on a path that does not exist is itself a Vector error, and
/// layouts differ per deployment (compose ships `sinks/`, the Rackspace
/// manifests do not). Staging creates the whole set unconditionally so the
/// validated directory list can be the same one Vector is launched with.
#[tokio::test]
async fn staging_creates_every_config_dir_even_when_the_active_tree_lacks_them() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    manager.stage_parsers(&[]).await.expect("stage");

    for subdir in STAGED_CONFIG_SUBDIRS {
        assert!(
            manager.staging_dir().join(subdir).is_dir(),
            "{subdir} missing from the candidate tree — `vector validate --config-dir` on a \
             missing path errors out, so validation would fail on the tree's own shape"
        );
    }
}

/// `sinks/` is one of the four `--config-dir` arguments in docker-compose.yml,
/// so a sink declared there is part of the graph being promoted and has to be
/// part of the graph being validated.
#[tokio::test]
async fn staging_carries_the_sinks_directory() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    let sinks = tmp.path().join("sinks");
    fs::create_dir_all(&sinks).await.expect("sinks");
    fs::write(
        sinks.join("extra.toml"),
        "[sinks.extra]\ntype = \"blackhole\"\n",
    )
    .await
    .expect("sink");
    // Not a config file Vector loads; must not be copied in as one.
    fs::write(sinks.join("clickhouse.toml.disabled"), "disabled")
        .await
        .expect("disabled");

    manager.stage_parsers(&[]).await.expect("stage");

    assert!(manager
        .staging_dir()
        .join("sinks")
        .join("extra.toml")
        .exists());
    assert!(
        !manager
            .staging_dir()
            .join("sinks")
            .join("clickhouse.toml.disabled")
            .exists(),
        "a .disabled file is not loaded by Vector, so staging it would validate a \
         component the running config does not have"
    );
}

// ---------------------------------------------------------------------------
// NAN-2305 Finding B — enrichment parsers are not log sources
// ---------------------------------------------------------------------------

/// The bug: the log/enrichment split existed for the collision check only, and
/// every writer below it was handed the FULL parser list. An enrichment parser
/// therefore got a per-parser TOML of its own — and `generate_source_config`
/// resolves an unrecognised `source_type` ("nano_enrich") to
/// `source_router.<safe_name>`, a route the router only emits for
/// "routed"/"vector" parsers. The staged tree was the NAN-2296 shape exactly: a
/// parser file consuming a route the router does not emit, fatal to the whole
/// Vector config — and promotion published it over the correct active one.
#[tokio::test]
async fn staged_enrichment_parsers_get_no_logs_pipeline_wiring() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    let parsers = vec![
        test_parser("Apache HTTP Server", "log", "routed"),
        enrichment_parser("Okta Identity"),
    ];
    manager.stage_parsers(&parsers).await.expect("stage");

    let staged = manager.staged_parsers_dir();
    assert!(
        staged.join("apache_http_server.toml").exists(),
        "precondition: the log parser is staged"
    );
    assert!(
        !staged.join("okta_identity.toml").exists(),
        "an enrichment parser got a per-parser log-pipeline TOML; the active writer emits \
         none, so staging diverges from deploy and promotion publishes the divergence"
    );

    let combiner = fs::read_to_string(staged.join("_combiner.toml"))
        .await
        .expect("combiner");
    assert!(
        !combiner.contains("okta_identity_output"),
        "the enrichment parser was unioned into db_parsers_combined, so its records enter \
         the LOGS pipeline as well as the enrichment lane"
    );

    let router = fs::read_to_string(staged.join("_router.toml"))
        .await
        .expect("router");
    assert!(
        !router.contains("\nokta_identity = "),
        "the enrichment parser got a source_router route"
    );
    // It must still be routed on the enrichment lane.
    assert!(
        router.contains("enrichment_router"),
        "precondition: the enrichment lane router is emitted"
    );
}

/// The consequence of the above, stated as the invariant that actually matters:
/// the staged tree must be internally coherent. This is the same check the
/// NAN-2301 backup gate applies to the active tree — a parser file consuming
/// `source_router.<x>` that `_router.toml` does not emit makes Vector reject the
/// entire config, and after promotion it also blocks the next backup, so the
/// deploy that would heal it has no rollback target.
#[tokio::test]
async fn the_staged_tree_has_no_dangling_router_inputs() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    let parsers = vec![
        test_parser("Apache HTTP Server", "log", "routed"),
        enrichment_parser("Okta Identity"),
    ];
    manager.stage_parsers(&parsers).await.expect("stage");

    let staged = manager.staged_parsers_dir();
    let routes = staged_router_routes(
        &fs::read_to_string(staged.join("_router.toml"))
            .await
            .expect("router"),
    );

    let mut entries = fs::read_dir(&staged).await.expect("staged dir");
    while let Some(entry) = entries.next_entry().await.expect("entry") {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".toml") || name == "_router.toml" {
            continue;
        }
        let body = fs::read_to_string(entry.path()).await.expect("read");
        for input in staged_source_router_inputs(&body) {
            assert!(
                routes.contains(&input),
                "{name} consumes source_router.{input}, which the staged router does not \
                 emit — Vector rejects the whole config on a dangling input"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// NAN-2305 Finding C — mirroring only deletes what this subsystem generated
// ---------------------------------------------------------------------------

/// The bug: mirroring deleted EVERY unpromoted `.toml`, including ones this
/// subsystem never wrote. A tenant-managed lane, or a file left by an older
/// version whose generator used different names, was destroyed on the first
/// deploy after upgrade — silently, and unrecoverably, because nothing here can
/// regenerate it. It still has to leave the loaded directory (that is the whole
/// point of NAN-2296), but it is moved, not deleted.
#[tokio::test]
async fn promotion_quarantines_a_toml_it_did_not_generate() {
    let (_tmp, manager) = staged_manager(
        &[
            ("apache.toml", "inputs = [\"source_router.apache\"]"),
            ("_router.toml", "shared"),
        ],
        &[(
            "tenant_custom_lane.toml",
            "[sinks.tenant_extra]\ntype = \"blackhole\"\n",
        )],
    )
    .await;

    manager.promote_staged().await.expect("promote");

    assert!(
        !manager.parsers_dir.join("tenant_custom_lane.toml").exists(),
        "an unpromoted file must leave the loaded directory — leaving it is the NAN-2296 \
         dangling-input outage"
    );
    assert_eq!(
        quarantined_names(&manager).await,
        vec![format!("tenant_custom_lane.toml{QUARANTINE_SUFFIX}")],
        "a file this subsystem never generated was DELETED rather than quarantined; \
         nothing here can rebuild it"
    );
    let batch = fs::read_dir(manager.quarantine_dir())
        .await
        .expect("quarantine root")
        .next_entry()
        .await
        .expect("batch")
        .expect("one batch");
    assert_eq!(
        fs::read_to_string(
            batch
                .path()
                .join(format!("tenant_custom_lane.toml{QUARANTINE_SUFFIX}"))
        )
        .await
        .unwrap(),
        "[sinks.tenant_extra]\ntype = \"blackhole\"\n",
        "the quarantined copy must be the file verbatim"
    );
}

/// The quarantined copy must stop being a `.toml`. `deploy/src/s3.js`'s config
/// sync walks the whole config root and uploads every `.toml` it finds, skipping
/// only `backup` and `staging` by name — a quarantined parser that kept its
/// extension would be replicated back out to every Vector pod, undoing the
/// quarantine.
#[tokio::test]
async fn quarantined_files_are_no_longer_toml() {
    let (_tmp, manager) = staged_manager(
        &[("_router.toml", "shared")],
        &[("tenant_custom_lane.toml", "tenant")],
    )
    .await;

    manager.promote_staged().await.expect("promote");

    for name in quarantined_names(&manager).await {
        assert!(
            !name.ends_with(".toml"),
            "{name} is still a .toml under the config root, so the S3 config sync will \
             republish it to the Vector pods it was removed from"
        );
    }
}

/// Under a Kubernetes ConfigMap mount every file in the config root is a symlink
/// into `..data/`. Staging must follow those links — refusing to would stage an
/// empty base tree on exactly the deployments where the config is delivered that
/// way, and `vector validate` would then judge a graph with no sources at all.
#[cfg(unix)]
#[tokio::test]
async fn base_configs_delivered_as_symlinks_are_staged() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    // The ConfigMap shape: real file in `..data/`, symlink beside it.
    let data = tmp.path().join("..data");
    fs::create_dir_all(&data).await.expect("..data");
    fs::write(data.join("00-base.toml"), "[sources.http]\ntype = \"http_server\"\n")
        .await
        .expect("real file");
    std::os::unix::fs::symlink(data.join("00-base.toml"), tmp.path().join("00-base.toml"))
        .expect("symlink");

    manager.stage_parsers(&[]).await.expect("stage");

    assert!(
        manager.staging_dir().join("00-base.toml").exists(),
        "a ConfigMap-delivered base config was skipped, so the candidate tree has no \
         sources and validation judges a graph nobody runs"
    );
}

/// The other half: NAN-2296's actual fix must survive the ownership boundary.
/// Once a promotion has recorded what it generated, the NEXT one deletes its own
/// rename orphans outright — including underscore-prefixed ones, since
/// `safe_name` maps non-alphanumerics to `_` and "(Legacy) Apache" is a PARSER
/// file named `_legacy__apache.toml`, not infrastructure.
#[tokio::test]
async fn promotion_deletes_a_rename_orphan_it_generated_itself() {
    let (_tmp, manager) = staged_manager(
        &[
            (
                "_legacy__apache.toml",
                "inputs = [\"source_router._legacy__apache\"]",
            ),
            ("_router.toml", "shared"),
        ],
        &[],
    )
    .await;

    // First promotion establishes ownership of `_legacy__apache.toml`.
    manager.promote_staged().await.expect("first promote");
    assert!(manager.parsers_dir.join("_legacy__apache.toml").exists());

    // The rename: the parser is now staged under its new name only.
    write_staging_tree(
        &manager,
        &[
            (
                "legacy_apache.toml",
                "inputs = [\"source_router.legacy_apache\"]",
            ),
            ("_router.toml", "shared"),
        ],
    )
    .await;
    mark_staging_complete(&manager).await;
    manager.promote_staged().await.expect("second promote");

    assert!(
        !manager.parsers_dir.join("_legacy__apache.toml").exists(),
        "the pre-rename file survived — it consumes a route the regenerated router no \
         longer emits, which makes the whole Vector config unloadable"
    );
    assert!(
        quarantined_names(&manager).await.is_empty(),
        "a file this subsystem generated itself must be deleted, not accumulated in \
         quarantine forever"
    );
    assert!(manager.parsers_dir.join("legacy_apache.toml").exists());
}

/// Infrastructure emitted under fixed names is ours whether or not a manifest
/// exists yet, so the OCSF→UDM transition still drops `_ocsf_sink.toml` on the
/// first deploy after upgrade instead of quarantining a file the active writer
/// deletes outright.
#[tokio::test]
async fn fixed_name_infrastructure_is_owned_without_a_manifest() {
    let (_tmp, manager) = staged_manager(
        &[("_router.toml", "shared"), ("_combiner.toml", "shared")],
        &[("_ocsf_sink.toml", "stale OCSF sink"), ("_ocsf.toml", "legacy")],
    )
    .await;

    manager.promote_staged().await.expect("promote");

    assert!(!manager.parsers_dir.join("_ocsf_sink.toml").exists());
    assert!(!manager.parsers_dir.join("_ocsf.toml").exists());
    assert!(
        quarantined_names(&manager).await.is_empty(),
        "generator-owned infrastructure was quarantined instead of deleted"
    );
}

// NAN-2305: colliding generated names must not reach the staging tree
// ---------------------------------------------------------------------------

/// Minimal enabled log `Parser`. Only `id`, `name`, `enabled` and
/// `match_values` matter to the staging guard.
fn staging_test_parser(id: u128, name: &str, match_value: &str) -> Parser {
    Parser {
        id: uuid::Uuid::from_u128(id),
        name: name.to_string(),
        description: None,
        source_type: "routed".to_string(),
        parser_vrl: String::new(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        enabled: true,
        validated: true,
        validation_error: None,
        category: None,
        vendor: None,
        product: None,
        kind: "log".to_string(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        namespace: "default".to_string(),
        timezone: "UTC".to_string(),
        match_values: Some(vec![match_value.to_string()]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// `promote_staged` copies the staged tree over the active one, so a collision
/// the active writer would have rejected still reaches disk by this route.
///
/// Distinct `match_values` keep the NAN-2247 source_type check quiet — it
/// guards the claim, not the generated namespace — so before this guard both
/// parsers were written to one `sources/parsers/my_source.toml` and emitted
/// the route key `my_source` twice into the staged `_router.toml`. A duplicate
/// key makes that TOML unparseable, which fails the whole pipeline rather than
/// one source.
#[tokio::test]
async fn staging_refuses_two_parsers_that_generate_one_filename() {
    let tmp = TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    let err = manager
        .stage_parsers(&[
            staging_test_parser(1, "My Source", "sysmon_json"),
            staging_test_parser(2, "my-source", "sysmon_xml"),
        ])
        .await
        .expect_err("two parsers generating one staged filename must fail");

    let msg = err.to_string();
    assert!(msg.contains("my_source"), "must name the identifier: {msg}");
    assert!(msg.contains("My Source"), "must name both claimants: {msg}");
    assert!(msg.contains("my-source"), "must name both claimants: {msg}");
    assert!(
        !manager
            .staging_dir()
            .join("sources")
            .join("parsers")
            .join("my_source.toml")
            .exists(),
        "a refused stage must write no parser config"
    );
}
