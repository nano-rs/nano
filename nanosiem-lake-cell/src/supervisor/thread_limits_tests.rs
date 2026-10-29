// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

fn config() -> CellConfig {
    serde_json::from_value(serde_json::json!({
        "cell_id": "cell-a", "data_dir": "/cell/data", "state_dir": "/s",
        "ingest_binary": "/b", "query_binary": "/b", "listen_unix": "/r.sock",
        "router_token_file": "/t", "placement_file": "/p", "dev_key_dir": "/k",
        "extra_ro_paths": ["/cell/release"]
    }))
    .unwrap()
}

fn delegated(root: &Path, controllers: &str) -> CgroupTree {
    std::fs::write(root.join("cgroup.controllers"), controllers).unwrap();
    std::fs::write(root.join("cgroup.procs"), "").unwrap();
    CgroupTree::adopt_root(root.into(), "/pod/cell".into(), vec![], false).unwrap()
}

#[test]
fn nan4834_shared_uids_get_the_tenant_allowance_before_delegation() {
    let cfg = config();
    let tenant = TenantId::new("tenant-a").unwrap();
    let ids = crate::uidmap::ids_for_slot(20_000, 20, 0).unwrap();
    assert_eq!(ids.uid(Role::Query), ids.uid(Role::Product));
    assert_eq!(ids.uid(Role::Ingest), ids.uid(Role::Maintenance));
    for (eps, allowance) in [(20.0, 512), (99.0, 512), (100.0, 1024), (2000.0, 1024)] {
        let placement = TenantPlacement::legacy(tenant.clone(), eps);
        let budget = TenantBudget::from_eps(eps);
        for role in Role::ALL {
            let jail = jail_spec_for(&cfg, &tenant, role, &ids, &budget, None, &placement);
            assert_eq!(jail.max_processes, Some(allowance), "{role:?}, {eps} eps");
        }
    }
}

#[test]
fn nan4834_delegated_assignments_use_the_aggregate_tenant_pids_boundary() {
    let cfg = config();
    let tenant = TenantId::new("tenant-a").unwrap();
    let ids = crate::uidmap::ids_for_slot(20_000, 20, 0).unwrap();
    let root = tempfile::tempdir().unwrap();
    let cgroups = delegated(root.path(), "cpu memory pids\n");
    let cap = CellCapacity {
        cpu_millicores: 16_000,
        memory_bytes: 32 * crate::budget::GIB,
        cpu_source: "test",
        memory_source: "test",
    };
    for eps in [20.0, 2000.0] {
        let placement = TenantPlacement::legacy(tenant.clone(), eps);
        let budget = TenantBudget::from_eps(eps);
        let limits = TenantLimits::from_placement(&placement, &cap, &cfg.resources);
        cgroups.ensure_tenant(&tenant, ids.slot, &limits).unwrap();
        for role in Role::ALL {
            let jail = jail_spec_for(
                &cfg,
                &tenant,
                role,
                &ids,
                &budget,
                Some(&cgroups),
                &placement,
            );
            assert_eq!(jail.max_processes, Some(budget.max_pids), "{role:?}");
            assert!(jail.cgroup_dir.is_some());
        }
        assert_eq!(
            std::fs::read_to_string(cgroups.tenant_dir(&tenant).join("pids.max")).unwrap(),
            budget.max_pids.to_string(),
            "removing UID subquotas must preserve the aggregate cap"
        );
    }
}

#[test]
fn nan4834_native_assignments_and_partial_delegation_keep_the_same_boundary() {
    use crate::contract::NativeChildService::{IngestPartsV1, LandingBytesV1, QueryPartsV1};
    let cfg = config();
    let tenant = TenantId::new("tenant-a").unwrap();
    let ids = crate::uidmap::ids_for_slot(20_000, 20, 0).unwrap();
    let placement = TenantPlacement::legacy(tenant.clone(), 20.0);
    let root = tempfile::tempdir().unwrap();
    let cgroups = delegated(root.path(), "cpu memory pids\n");
    cgroups.register(&tenant, ids.slot);
    assert!(
        native_role_preflight(
            &cfg,
            &tenant,
            Role::Query,
            &ids,
            None,
            &placement,
            QueryPartsV1
        )
        .is_err(),
        "native roles still require a cgroup"
    );
    let partial_root = tempfile::tempdir().unwrap();
    let partial = delegated(partial_root.path(), "cpu memory\n");
    partial.register(&tenant, ids.slot);
    for (role, service) in [
        (Role::Query, QueryPartsV1),
        (Role::Ingest, IngestPartsV1),
        (Role::Landing, LandingBytesV1),
    ] {
        for (tree, expected) in [(Some(&partial), Some(512)), (Some(&cgroups), Some(512))] {
            let assignment =
                native_role_preflight(&cfg, &tenant, role, &ids, tree, &placement, service)
                    .unwrap();
            assert_eq!(assignment.jail.max_processes, expected, "{role:?}");
            crate::child::validate_native_assignment(
                &[service],
                PROTOCOL_VERSION,
                service,
                &assignment,
                &[],
            )
            .unwrap();
        }
    }
}

/// Use the production trusted-local sizer, including its auxiliary budgets.
fn local_placement(memory: u64, cpus: u32) -> TenantPlacement {
    let s = crate::trusted_local::size(memory, cpus);
    let mut p = TenantPlacement::legacy(TenantId::new("tenant-a").unwrap(), s.eps as f64);
    for (role, (request_millicores, limit_millicores, request_memory_bytes, limit_memory_bytes)) in
        [(Role::Ingest, s.ingest), (Role::Detect, s.detect), (Role::Query, s.query)] {
        let b = crate::config::RoleBudget { request_millicores, limit_millicores,
            request_memory_bytes, limit_memory_bytes };
        match role {
            Role::Ingest => {
                p.ingest_request_millicores = Some(b.request_millicores);
                p.ingest_limit_millicores = Some(b.limit_millicores);
                p.ingest_request_memory_bytes = Some(b.request_memory_bytes);
                p.ingest_limit_memory_bytes = Some(b.limit_memory_bytes);
            }
            Role::Detect => {
                p.detect_request_millicores = Some(b.request_millicores);
                p.detect_limit_millicores = Some(b.limit_millicores);
                p.detect_request_memory_bytes = Some(b.request_memory_bytes);
                p.detect_limit_memory_bytes = Some(b.limit_memory_bytes);
            }
            Role::Query => {
                p.query_request_millicores = Some(b.request_millicores);
                p.query_limit_millicores = Some(b.limit_millicores);
                p.query_request_memory_bytes = Some(b.request_memory_bytes);
                p.query_limit_memory_bytes = Some(b.limit_memory_bytes);
            }
            _ => unreachable!(),
        }
    }
    p.local_resources = Some(s.local_resources);
    p
}

#[test]
fn nan4834_device_sizing_survives_adoption_and_keeps_a_finite_aggregate_cap() {
    let mut cfg = config();
    cfg.trusted_local = true;
    let ids = crate::uidmap::ids_for_slot(20_000, 20, 0).unwrap();
    let root = tempfile::tempdir().unwrap();
    let cgroups = delegated(root.path(), "cpu memory pids\n");
    for (memory, cpus, expected) in [
        (2 * crate::budget::GIB, 4, 576),
        // The query memory floor leaves this small placement below 100 EPS;
        // six four-thread roles need 192 fixed + 384 native tasks.
        (3_413_114_880, 4, 576),
        (32 * crate::budget::GIB, 16, 1728),
        (256 * crate::budget::GIB, 64, 6336),
    ] {
        let p = local_placement(memory, cpus);
        let budget = TenantBudget::from_eps(p.eps);
        let allowance = crate::budget::tenant_task_allowance(&p);
        assert_eq!(allowance, expected, "{memory} bytes / {cpus} CPUs");
        let cap = CellCapacity { cpu_millicores: cpus * 1000, memory_bytes: memory,
            cpu_source: "test", memory_source: "test" };
        let limits = TenantLimits::from_placement(&p, &cap, &cfg.resources);
        assert_eq!(limits.max_pids, allowance);
        cgroups.ensure_tenant(&p.tenant_id, ids.slot, &limits).unwrap();
        assert_eq!(std::fs::read_to_string(cgroups.tenant_dir(&p.tenant_id).join("pids.max")).unwrap(),
            allowance.to_string());
        // The immutable child limit is independent of delegation. A larger
        // device must not inherit the former 512/1024 ceiling at startup.
        for role in Role::ALL {
            let before = jail_spec_for(&cfg, &p.tenant_id, role, &ids, &budget, None, &p);
            let after = jail_spec_for(&cfg, &p.tenant_id, role, &ids, &budget, Some(&cgroups), &p);
            assert_eq!(after.max_processes, Some(allowance));
            assert_eq!(before.max_processes, Some(allowance.min(crate::resources::detect_pids_max(None).unwrap_or(u64::MAX))));
        }
    }
    // A real pod boundary wins even when it is below the safety floor.
    std::fs::write(root.path().join("pids.max"), "400").unwrap();
    let p = local_placement(256 * crate::budget::GIB, 64);
    let assignment = native_role_preflight(&cfg, &p.tenant_id, Role::Query, &ids,
        Some(&cgroups), &p, NativeChildService::QueryPartsV1).unwrap();
    assert_eq!(assignment.jail.max_processes, Some(400));
}

#[test]
fn nan4834_partial_delegation_retains_the_scaled_watchdog_ceiling() {
    let placements = [local_placement(256 * crate::budget::GIB, 64),
        TenantPlacement::legacy(TenantId::new("tenant-b").unwrap(), 20.0)];
    let expected = Some(6336 + 1024 + 1024);
    assert_eq!(crate::resources::watchdog_pids_ceiling(&placements, None), expected);
    for (controllers, ceiling) in [("cpu memory", expected), ("cpu memory pids", None)] {
        let root = tempfile::tempdir().unwrap();
        let cgroups = delegated(root.path(), controllers);
        assert_eq!(crate::resources::watchdog_pids_ceiling(&placements, Some(&cgroups)), ceiling);
    }
}
