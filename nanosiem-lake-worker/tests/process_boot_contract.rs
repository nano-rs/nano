// SPDX-License-Identifier: AGPL-3.0-or-later

//! Keep new executables from silently inheriting the container's low soft limit.
#[test]
fn every_lake_binary_initializes_limits_before_application_work() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = vec![root.join("main.rs")];
    sources.extend(
        std::fs::read_dir(root.join("bin"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "rs")),
    );
    assert!(sources.len() >= 31);
    // A cell child's tracing init: the raw subscriber or the shared
    // `cell_logging` helper (NAN-2964). Either must come after the limits.
    let tracing_at = |text: &str| {
        ["tracing_subscriber::fmt()", "nanosiem_lake_worker::cell_logging::init_child_tracing()"]
            .iter()
            .filter_map(|marker| text.find(marker))
            .min()
    };
    for path in sources {
        let source = std::fs::read_to_string(&path).unwrap();
        if path.file_name().is_some_and(|name| name == "lake_native_init_bench.rs") {
            // The native probe wraps run() so it can use _exit after chDB.
            let (_, run) = source.split_once("fn run() -> Result<()> {")
                .expect("native probe run entry");
            assert!(run.trim_start().starts_with("nanosiem_lake_worker::process_limits::initialize()?;"));
            let (_, main) = source.split_once("fn main() {").expect("native probe main");
            assert!(main.contains("match run()"));
            continue;
        }
        let (_, main) = source
            .split_once("fn main() -> Result<()> {")
            .or_else(|| source.split_once("fn main() -> anyhow::Result<()> {"))
            .expect("binary main signature");
        if path.file_name().is_some_and(|name| name == "lake_part_query.rs") {
            let bootstrap = main.find("let boot = nanosiem_lake_cell::child::bootstrap_with_native_init(")
                .expect("query child bootstraps before process-wide work");
            let limits = main[bootstrap..].find("nanosiem_lake_worker::process_limits::initialize()?;")
                .expect("query child initializes limits after jail") + bootstrap;
            let runtime = tracing_at(&main[limits..])
                .expect("query child initializes runtime") + limits;
            let native = main[bootstrap..].find("nanosiem_lake_worker::native::initialize_cell_runtime()?;")
                .expect("query/detect preload native runtime before confinement") + bootstrap;
            assert!(bootstrap < native && native < limits && limits < runtime, "{} boot order regressed", path.display());
            continue;
        }
        if path.file_name().is_some_and(|name| name == "lake_part_ingest.rs") {
            let bootstrap = main.find("let boot = nanosiem_lake_cell::child::bootstrap()?;")
                .expect("cell child bootstraps before process-wide work");
            let child_limits = main[bootstrap..].find("nanosiem_lake_worker::process_limits::initialize()?;")
                .expect("cell child initializes limits after jail") + bootstrap;
            let child_runtime = tracing_at(&main[child_limits..])
                .expect("cell child initializes runtime") + child_limits;
            let lab_limits = main[child_runtime..].find("nanosiem_lake_worker::process_limits::initialize()?;")
                .expect("lab initializes limits before runtime") + child_runtime;
            let lab_runtime = tracing_at(&main[lab_limits..])
                .expect("lab initializes runtime") + lab_limits;
            assert!(bootstrap < child_limits && child_limits < child_runtime && child_runtime < lab_limits && lab_limits < lab_runtime,
                "{} boot order regressed", path.display());
            continue;
        }
        if path.file_name().is_some_and(|name| name == "lake_search_bench.rs") {
            // This wrapper delegates to the lab entry point, checked separately.
            assert!(main.contains("lab::main()"));
            assert!(source.contains("#[path = \"lake_part_query_lab.rs\"]"));
            continue;
        }
        if path.file_name().is_some_and(|name| name == "lake_job_runner.rs") {
            // The existing --help fast path exits without application work.
            let limits = main.find("nanosiem_lake_worker::process_limits::initialize()?;").unwrap();
            let tracing = tracing_at(main).unwrap();
            let arguments = main.find("let mut arguments = Arguments::parse(").unwrap();
            assert!(limits < tracing && tracing < arguments);
            continue;
        }
        assert!(
            main.trim_start()
                .starts_with("nanosiem_lake_worker::process_limits::initialize()?;"),
            "{} skips boot limits",
            path.display()
        );
    }
}
