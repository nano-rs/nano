// SPDX-License-Identifier: AGPL-3.0-or-later

/// Keep one multi-file statement and let its file sources do the decoding.
///
/// The v3 Parquet reader treats max_parsing_threads=1 as inline parsing,
/// without its nested decoder pool. When enough files can occupy the role's
/// query threads, those source workers already provide decode parallelism.
/// Avoid handing each small file's tasks to another pool and waiting for
/// them back. With fewer files, preserve the native pool so a single large
/// file can still use the allocated cores. Later thread grants only lower
/// the query's role ceiling and preserve the inline sentinel.
///
/// This changes no file selection, batching, prefetch or session lifetime.
/// In particular it does not add a cache or turn one scan into N statements.
pub(super) fn inline_file_parsing(sql: String, files: usize, role_threads: u64) -> String {
    // An operator probe may explicitly compare parser modes within its
    // validated role cap. Leave that setting to the probe and final grant;
    // installing the inline sentinel first would make its tighten-only
    // setting application silently refuse a pooled comparison.
    let explicit_probe = crate::perf_overrides::probe_settings()
        .iter()
        .any(|(name, _)| *name == "max_parsing_threads");
    if explicit_probe || role_threads == 0 || (files as u128) < u128::from(role_threads) {
        return sql;
    }
    crate::executor::with_setting(&sql, "max_parsing_threads=1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::part_query::lanes::setting;
    use crate::thread_budget::{Priority, ThreadBudget};

    #[test]
    fn cgroup_role_budget_drives_parser_policy_and_shrinking_grants() {
        use crate::part_query::memory_budget::{QueryMemoryBudget, GIB};

        for (memory, cpu, expected_threads) in [
            (2 * GIB, 8_000, 4),
            (32 * GIB, 16_000, 16),
            (64 * GIB, 32_000, 32),
        ] {
            let root = tempfile::tempdir().unwrap();
            let leaf = root.path().join("tenant/query");
            std::fs::create_dir_all(&leaf).unwrap();
            std::fs::write(leaf.join("memory.max"), memory.to_string()).unwrap();
            std::fs::write(
                leaf.join("cpu.max"),
                nanosiem_lake_cell::resources::cpu_max_line(cpu),
            ).unwrap();
            let cgroup = crate::cgroup_memory::resolve(
                root.path(), "0::/", "", Some(std::path::Path::new("tenant/query")),
            );
            let (budget, classes) = QueryMemoryBudget::for_cgroup(memory, cpu, &cgroup).with_classes();
            let (threads, memory) = crate::part_query::server::role_statement_limits(&budget, classes);
            assert_eq!(threads, expected_threads);
            let sql = format!("SELECT 1 SETTINGS max_threads={threads}, max_memory_usage={memory}");
            let pool = ThreadBudget::new(threads);
            let held = pool.grant(Priority::Interactive);
            let next = pool.grant(Priority::Interactive);
            assert!(next.threads() < threads);
            for files in [threads as usize - 1, threads as usize] {
                let planned = inline_file_parsing(sql.clone(), files, threads);
                let inline = files as u64 >= threads;
                assert_eq!(setting(&planned, "max_parsing_threads"), inline.then_some(1));
                let applied = next.apply(&planned);
                assert_eq!(setting(&applied, "max_threads"), Some(next.threads()));
                assert_eq!(setting(&applied, "max_parsing_threads"), Some(if inline { 1 } else { next.threads() }));
                assert_eq!(setting(&applied, "max_memory_usage"), Some(memory));
            }
            drop(held);
        }
    }

    #[test]
    fn sources_supply_parallelism_at_the_role_ceiling_and_survive_smaller_grants() {
        for threads in [1, 2, 4, 16] {
            let sql = format!("SELECT 1 SETTINGS max_threads={threads}");
            for files in [0, 1, 8, 28] {
                let planned = inline_file_parsing(sql.clone(), files, threads);
                if files == 0 || (files as u64) < threads {
                    assert_eq!(
                        planned, sql,
                        "preserve native parallelism: {threads}/{files}"
                    );
                } else {
                    assert_eq!(setting(&planned, "max_parsing_threads"), Some(1));
                    // A process grant may shrink, but must never turn inline
                    // parsing back into a separate pool or raise max_threads.
                    let budget = ThreadBudget::new(threads);
                    let held = budget.grant(Priority::Interactive);
                    let next = budget.grant(Priority::Interactive);
                    let applied = next.apply(&planned);
                    assert_eq!(setting(&applied, "max_parsing_threads"), Some(1));
                    assert!(setting(&applied, "max_threads").unwrap() <= threads);
                    drop(held);
                }
            }
        }
    }

    #[tokio::test]
    async fn explicit_operator_parser_mode_remains_within_the_process_grant() {
        let scope = crate::perf_overrides::Parsed {
            probe: Some(crate::perf_overrides::Probe {
                settings: vec![("max_parsing_threads", "2".to_string())],
                ..Default::default()
            }),
            ..Default::default()
        };
        let sql = "SELECT 1 SETTINGS max_threads=2";
        let planned = crate::perf_overrides::scoped(Some(std::sync::Arc::new(scope)), async {
            inline_file_parsing(sql.to_string(), 28, 2)
        })
        .await;
        assert_eq!(planned, sql);
        let pooled = crate::part_query::sql_probe::apply_settings(
            &planned,
            &[("max_parsing_threads", "2".to_string())],
        );
        let budget = ThreadBudget::new(2);
        let applied = budget.grant(Priority::Interactive).apply(&pooled);
        assert_eq!(setting(&applied, "max_parsing_threads"), Some(2));
        assert_eq!(setting(&applied, "max_threads"), Some(2));
    }
}
