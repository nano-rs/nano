//! Resource watchdog against real processes (NAN-2872). No privileges
//! needed: "tenants" here are child processes of this test (membership by
//! ancestry), so the watchdog may signal them as the same uid.
//!
//! - a memory hog over its hard ceiling is SIGKILLed; a tenant within its
//!   guarantee next to it is untouched;
//! - cell memory critical: the victim is the tenant furthest over its
//!   guarantee, never the bigger one within its guarantee;
//! - a CPU spinner bursts freely while the cell has headroom;
//! - a CPU spinner over its ceiling is duty-cycled down to it (and survives);
//! - under contention the over-share spinner is throttled while a spinner
//!   within its guarantee keeps running unthrottled.
//!
//! Children re-execute this test binary in helper mode (`helper` test +
//! `NANO_WD_HELPER`), with PR_SET_PDEATHSIG so nothing outlives the test.

use nanosiem_lake_cell::budget::MIB;
use nanosiem_lake_cell::config::ResourceConfig;
use nanosiem_lake_cell::contract::TenantId;
use nanosiem_lake_cell::procfs;
use nanosiem_lake_cell::resources::{CellCapacity, EventKind, KillReason, ThrottleReason, TenantLimits};
use nanosiem_lake_cell::watchdog::{Monitor, TenantSpec, TickOutput};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const HELPER: &str = "NANO_WD_HELPER";

/// Helper mode: `mem:<MiB>` holds that much anonymous memory, `spin`
/// burns one core. Both live until killed (or 120 s).
#[test]
fn helper() {
    let Ok(mode) = std::env::var(HELPER) else { return };
    if let Some(mb) = mode.strip_prefix("mem:") {
        let mb: usize = mb.parse().unwrap();
        let mut hold = Vec::with_capacity(mb);
        for _ in 0..mb {
            let mut chunk = vec![0u8; 1 << 20];
            for i in (0..chunk.len()).step_by(4096) {
                chunk[i] = 1;
            }
            hold.push(chunk);
        }
        std::thread::sleep(Duration::from_secs(120));
        drop(hold);
    } else if mode == "spin" {
        let end = Instant::now() + Duration::from_secs(120);
        let mut x = 0u64;
        while Instant::now() < end {
            for i in 0..100_000u64 {
                x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(i));
            }
        }
    }
}

fn spawn(mode: &str) -> Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["helper", "--exact", "--nocapture", "--test-threads=1"]).env(HELPER, mode);
    // SAFETY: prctl only.
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            Ok(())
        });
    }
    cmd.stdout(std::process::Stdio::null()).spawn().unwrap()
}

/// Anon memory of `pid` and its descendants (the harness forks nothing, but
/// the helper is the libtest process itself).
fn anon_of(pid: u32) -> u64 {
    procfs::scan().iter().filter(|p| p.pid == pid).map(|p| p.memory(procfs::MemoryMetric::Anon)).sum()
}

fn wait_anon(pid: u32, at_least: u64) {
    let t0 = Instant::now();
    while anon_of(pid) < at_least {
        assert!(t0.elapsed() < Duration::from_secs(30), "helper {pid} never reached {at_least} bytes");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn cpu_ticks(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| procfs::parse_stat(&s)).map(|s| s.own_ticks).unwrap_or(0)
}

/// Millicores `pid` used over `d`.
fn cpu_rate(pid: u32, d: Duration) -> f64 {
    let a = cpu_ticks(pid);
    std::thread::sleep(d);
    let b = cpu_ticks(pid);
    (b - a) as f64 * 1000.0 / procfs::clk_tck() as f64 / d.as_secs_f64()
}

fn tid(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}

fn limits(g_cpu: u32, ceiling: u32, g_mem: u64, soft: u64, hard: u64) -> TenantLimits {
    TenantLimits {
        cpu_guarantee_millicores: g_cpu,
        cpu_ceiling_millicores: ceiling,
        cpu_weight: g_cpu,
        memory_guarantee_bytes: g_mem,
        memory_soft_bytes: soft,
        memory_hard_bytes: hard,
        max_pids: 512,
        io_weight: 100,
    }
}

fn key_of(pid: u32) -> (u32, u64) {
    let st = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| procfs::parse_stat(&s)).unwrap();
    (pid, st.starttime)
}

fn spec(t: &str, l: TenantLimits, child: &Child) -> TenantSpec {
    TenantSpec { tenant: tid(t), limits: l, roots: vec![key_of(child.id())], uids: vec![], exempt: vec![], unthrottled_uids: vec![] }
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

/// A cell far bigger than this machine: no contention from the host's own
/// load (this test sees every process on the box, not just a pod's).
fn huge() -> CellCapacity {
    CellCapacity { cpu_millicores: 10_000_000, memory_bytes: 1 << 50, cpu_source: "config", memory_source: "config" }
}

fn cfg() -> ResourceConfig {
    ResourceConfig { interval_ms: 200, cpu_smoothing_secs: 0.5, throttle_period_ms: 50, ..Default::default() }
}

fn run(m: &mut Monitor, specs: &[TenantSpec], ticks: usize, every: Duration) -> Vec<TickOutput> {
    (0..ticks)
        .map(|_| {
            std::thread::sleep(every);
            m.tick(specs, None)
        })
        .collect()
}

fn reap(mut c: Child) -> Option<i32> {
    let t0 = Instant::now();
    loop {
        if let Some(st) = c.try_wait().unwrap() {
            return st.signal();
        }
        if t0.elapsed() > Duration::from_secs(5) {
            let _ = c.kill();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn memory_hog_over_its_hard_ceiling_is_killed_neighbour_untouched() {
    let hog = spawn("mem:300");
    let calm = spawn("mem:40");
    wait_anon(hog.id(), 290 * MIB);
    wait_anon(calm.id(), 35 * MIB);
    let specs = [
        spec("hog", limits(50, 500, 64 * MIB, 128 * MIB, 200 * MIB), &hog),
        spec("calm", limits(50, 500, 64 * MIB, 128 * MIB, 200 * MIB), &calm),
    ];
    let mut m = Monitor::new(cfg(), huge(), false);
    let out = run(&mut m, &specs, 2, Duration::from_millis(100));
    let kills: Vec<_> = out.iter().flat_map(|o| &o.kills).collect();
    assert_eq!(kills.len(), 1, "{kills:?}");
    let k = kills[0];
    assert_eq!((k.tenant.as_str(), k.pid, k.reason), ("hog", hog.id(), KillReason::MemoryHardCeiling));
    assert!(k.observed_bytes >= 290 * MIB && k.limit_bytes == 200 * MIB);
    let ev = out.iter().flat_map(|o| &o.events).find(|e| e.kind == EventKind::Killed).unwrap();
    assert_eq!((ev.reason.as_str(), ev.unit, ev.pid), ("memory_hard_ceiling", "bytes", Some(hog.id())));
    k.kill();
    assert_eq!(reap(hog), Some(libc::SIGKILL));
    assert!(calm_alive(&calm), "the neighbour must survive");
    let mut calm = calm;
    let _ = calm.kill();
    let _ = calm.wait();
}

fn calm_alive(c: &Child) -> bool {
    std::fs::read_to_string(format!("/proc/{}/stat", c.id())).is_ok_and(|s| !s.contains(") Z "))
}

#[test]
fn cell_memory_critical_kills_the_largest_overage_only() {
    // "within" holds more memory but inside its guarantee; "over" is
    // smaller but furthest over its guarantee.
    let within = spawn("mem:160");
    let over = spawn("mem:100");
    wait_anon(within.id(), 150 * MIB);
    wait_anon(over.id(), 95 * MIB);
    // A cell whose memory is already critical from the host's processes.
    let tiny = CellCapacity { cpu_millicores: 10_000_000, memory_bytes: 64 * MIB, cpu_source: "config", memory_source: "config" };
    let specs = [
        spec("within", limits(50, 500, 512 * MIB, 1024 * MIB, 2048 * MIB), &within),
        spec("over", limits(50, 500, 16 * MIB, 1024 * MIB, 2048 * MIB), &over),
    ];
    let mut m = Monitor::new(cfg(), tiny, false);
    let out = run(&mut m, &specs, 1, Duration::from_millis(50));
    let kills: Vec<_> = out.iter().flat_map(|o| &o.kills).collect();
    assert_eq!(kills.len(), 1, "{kills:?}");
    assert_eq!((kills[0].tenant.as_str(), kills[0].reason), ("over", KillReason::CellMemoryCritical));
    kills[0].kill();
    assert_eq!(reap(over), Some(libc::SIGKILL));
    // Next passes (cooldown over): "within" is still never chosen.
    std::thread::sleep(Duration::from_millis(2100));
    let specs = [spec("within", limits(50, 500, 512 * MIB, 1024 * MIB, 2048 * MIB), &within)];
    let out = run(&mut m, &specs, 2, Duration::from_millis(100));
    assert!(out.iter().all(|o| o.kills.is_empty()), "a tenant within its guarantee was chosen");
    assert!(out.iter().flat_map(|o| &o.events).any(|e| e.kind == EventKind::CellMemoryCriticalNoVictim));
    assert!(calm_alive(&within));
    let mut within = within;
    let _ = within.kill();
    let _ = within.wait();
}

#[test]
fn cpu_burst_is_allowed_with_headroom() {
    let spinner = spawn("spin");
    let specs = [spec("burst", limits(50, 4000, 64 * MIB, 128 * MIB, 1024 * MIB), &spinner)];
    let mut m = Monitor::new(cfg(), huge(), false);
    let out = run(&mut m, &specs, 10, Duration::from_millis(200));
    assert!(out.iter().all(|o| o.events.iter().all(|e| e.kind != EventKind::Throttled)), "burst must not be throttled");
    let used = out.last().unwrap().samples[0].cpu_millicores;
    // 20× its 50 mc guarantee (one core, minus whatever the box is doing).
    assert!(used > 300.0, "spinner measured at {used} mc");
    let v = m.tenant_view(&tid("burst")).unwrap();
    assert!(v.throttle.is_none() && v.over_guarantee_secs < 60);
    let mut spinner = spinner;
    let _ = spinner.kill();
    let _ = spinner.wait();
}

#[test]
fn cpu_spinner_over_its_ceiling_is_duty_cycled_not_killed() {
    let spinner = spawn("spin");
    let pid = spinner.id();
    let before = cpu_rate(pid, Duration::from_millis(600));
    let specs = [spec("spin", limits(50, 200, 64 * MIB, 128 * MIB, 1024 * MIB), &spinner)];
    let mut m = Monitor::new(cfg(), huge(), false);
    let out = run(&mut m, &specs, 5, Duration::from_millis(200));
    let ev = out.iter().flat_map(|o| &o.events).find(|e| e.kind == EventKind::Throttled).expect("throttled");
    assert_eq!((ev.reason.as_str(), ev.limit, ev.unit), ("cpu_ceiling", 200.0, "millicores"));
    assert_eq!(m.tenant_view(&tid("spin")).unwrap().throttle.unwrap().reason, ThrottleReason::Ceiling);
    // Keep the loop running while measuring (duty adapts per tick).
    let t0 = Instant::now();
    let a = cpu_ticks(pid);
    while t0.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(200));
        let o = m.tick(&specs, None);
        assert!(o.kills.is_empty(), "CPU never kills");
    }
    let throttled = (cpu_ticks(pid) - a) as f64 * 1000.0 / procfs::clk_tck() as f64 / t0.elapsed().as_secs_f64();
    println!("spinner: {before:.0} mc unthrottled, {throttled:.0} mc throttled to a 200 mc ceiling");
    assert!(throttled < 450.0 && throttled < before * 0.6, "not throttled: {before:.0} → {throttled:.0} mc");
    // Release continues it: dropping the monitor SIGCONTs.
    drop(m);
    std::thread::sleep(Duration::from_millis(100));
    let after = cpu_rate(pid, Duration::from_millis(500));
    assert!(after > throttled, "not continued after release: {after:.0} mc");
    let mut spinner = spinner;
    let _ = spinner.kill();
    let _ = spinner.wait();
}

/// NAN-3008: a process under an unthrottled uid (the tenant's query[T]) is
/// measured and the tenant is still reported throttled, but it is never
/// SIGSTOPped, so interactive search keeps its CPU.
#[test]
fn unthrottled_uid_is_measured_but_never_duty_cycled() {
    let spinner = spawn("spin");
    let pid = spinner.id();
    let before = cpu_rate(pid, Duration::from_millis(600));
    let mut spec = spec("query", limits(50, 200, 64 * MIB, 128 * MIB, 1024 * MIB), &spinner);
    spec.unthrottled_uids = vec![unsafe { libc::getuid() }];
    let specs = [spec];
    let mut m = Monitor::new(cfg(), huge(), false);
    let out = run(&mut m, &specs, 5, Duration::from_millis(200));
    assert!(out.iter().flat_map(|o| &o.events).any(|e| e.kind == EventKind::Throttled), "still measured over its ceiling");
    let t0 = Instant::now();
    let a = cpu_ticks(pid);
    while t0.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(200));
        m.tick(&specs, None);
    }
    let during = (cpu_ticks(pid) - a) as f64 * 1000.0 / procfs::clk_tck() as f64 / t0.elapsed().as_secs_f64();
    println!("unthrottled spinner: {before:.0} mc before, {during:.0} mc while its tenant is throttled");
    assert!(during > before * 0.7, "unthrottled uid was duty-cycled: {before:.0} → {during:.0} mc");
    drop(m);
    let mut spinner = spinner;
    let _ = spinner.kill();
    let _ = spinner.wait();
}

#[test]
fn contention_throttles_the_over_share_tenant_and_spares_one_within_its_guarantee() {
    let greedy = spawn("spin");
    let entitled = spawn("spin");
    // A 1-core cell: two spinners (~2 cores of demand) contend.
    let cell = CellCapacity { cpu_millicores: 1000, memory_bytes: 1 << 50, cpu_source: "config", memory_source: "config" };
    let specs = [
        spec("greedy", limits(100, 1000, 64 * MIB, 128 * MIB, 1024 * MIB), &greedy),
        // Guaranteed a full core: its ~1000 mc demand is within it.
        spec("entitled", limits(1000, 2000, 64 * MIB, 128 * MIB, 1024 * MIB), &entitled),
    ];
    let mut m = Monitor::new(cfg(), cell, false);
    let out = run(&mut m, &specs, 8, Duration::from_millis(200));
    let throttled: Vec<_> = out.iter().flat_map(|o| &o.events).filter(|e| e.kind == EventKind::Throttled).collect();
    assert!(throttled.iter().any(|e| e.tenant.as_ref().is_some_and(|t| t.as_str() == "greedy") && e.reason == "cpu_contention"),
        "{throttled:?}");
    assert!(throttled.iter().all(|e| e.tenant.as_ref().is_none_or(|t| t.as_str() != "entitled")), "{throttled:?}");
    // Its share: what the cell (sized to Σ guarantees = 1100 mc) has left
    // after entitled's demand; ≥ its 100 mc guarantee. On an idle box
    // entitled uses ~1000 mc → 100; a loaded box leaves greedy a bit more.
    let v = m.tenant_view(&tid("greedy")).unwrap();
    let th = v.throttle.expect("greedy throttled");
    assert_eq!(th.reason, ThrottleReason::Contention);
    assert!((100..=600).contains(&th.target_millicores), "target {}", th.target_millicores);
    assert!(m.tenant_view(&tid("entitled")).unwrap().throttle.is_none());
    assert!(m.cell_view().cpu_contended);
    // Enforcement: greedy runs at a fraction of entitled.
    let (g0, e0, t0) = (cpu_ticks(greedy.id()), cpu_ticks(entitled.id()), Instant::now());
    while t0.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(200));
        m.tick(&specs, None);
    }
    let (g, e) = ((cpu_ticks(greedy.id()) - g0) as f64, (cpu_ticks(entitled.id()) - e0) as f64);
    println!("contention: greedy {g} ticks, entitled {e} ticks over 2 s");
    assert!(g < e * 0.6, "greedy {g} vs entitled {e} ticks");
    drop(m);
    for mut c in [greedy, entitled] {
        let _ = c.kill();
        let _ = c.wait();
    }
}

/// H1: a tenant with ~1,000 processes is measured and duty-cycled without
/// the watchdog holding a pidfd per process.
#[test]
fn a_thousand_tenant_processes_do_not_exhaust_fds() {
    // One root (sh) with 1,000 sleeping children, in its own process group.
    let mut root = Command::new("sh");
    root.args(["-c", "i=0; while [ $i -lt 1000 ]; do sleep 60 & i=$((i+1)); done; wait"]).process_group(0);
    let mut root = root.spawn().unwrap();
    let pgid = root.id() as i32;
    let t0 = Instant::now();
    let count = || procfs::scan().iter().filter(|p| p.stat.ppid == pgid as u32).count();
    while count() < 1000 {
        assert!(t0.elapsed() < Duration::from_secs(60), "only {} children", count());
        std::thread::sleep(Duration::from_millis(100));
    }
    // A ceiling of 1 mc and a fake demand: force a throttle by spinning in
    // the root's group is overkill; instead check measurement + an idle
    // duty cycle over all 1,001 members with a zero-headroom ceiling.
    let specs = [TenantSpec {
        tenant: tid("many"),
        limits: limits(1, 1, 64 * MIB, 1 << 40, 1 << 41),
        roots: vec![key_of(root.id())],
        uids: vec![],
        exempt: vec![],
        unthrottled_uids: vec![],
    }];
    let before = open_fds();
    // A thousand idle `sleep` processes can have zero anonymous RSS in a
    // minimal CI image; resident RSS still proves every process is measured.
    let mut sample_cfg = cfg();
    sample_cfg.memory_metric = procfs::MemoryMetric::Rss;
    let mut m = Monitor::new(sample_cfg, huge(), false);
    let mut peak = 0;
    for _ in 0..5 {
        std::thread::sleep(Duration::from_millis(200));
        let o = m.tick(&specs, None);
        assert!(o.samples[0].memory_bytes > 0);
        peak = peak.max(open_fds());
    }
    println!("fds: {before} before, peak {peak} during 5 ticks over 1,001 tenant processes");
    assert!(peak < before + 50, "fd use grows with tenant processes: {before} -> {peak}");
    // SAFETY: kill the whole group.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    let _ = root.wait();
}

/// M2: the desired throttle is re-applied every tick, so it survives a
/// recreated cgroup (role stop) and a placement change (ensure_tenant).
#[test]
fn delegated_throttle_survives_cgroup_recreation_and_resize() {
    use nanosiem_lake_cell::limits::CgroupTree;
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("cgroup.controllers"), "cpu memory pids\n").unwrap();
    std::fs::write(d.path().join("cgroup.procs"), "").unwrap();
    let tree = CgroupTree::adopt_root(d.path().to_path_buf(), "/".into(), vec![], true).unwrap();
    let spinner = spawn("spin");
    // Created at a 2000 mc ceiling: the 200 mc throttle below is the
    // watchdog's write, not ensure_tenant's.
    let l = limits(50, 200, 64 * MIB, 128 * MIB, 1024 * MIB);
    tree.ensure_tenant(&tid("spin"), 3, &TenantLimits { cpu_ceiling_millicores: 2000, ..l }).unwrap();
    assert_eq!(std::fs::read_to_string(d.path().join("tenants/s3/cpu.max")).unwrap(), "200000 100000");
    let cpu_max = || std::fs::read_to_string(d.path().join("tenants/s3/cpu.max")).unwrap();
    let specs = [spec("spin", l, &spinner)];
    let mut m = Monitor::new(cfg(), huge(), true);
    run_cg(&mut m, &specs, 4, &tree);
    assert_eq!(cpu_max(), "20000 100000", "throttled to the 200 mc ceiling");
    // Placement change: bigger ceiling in the cgroup, the throttle stays.
    let bigger = TenantLimits { cpu_ceiling_millicores: 300, ..l };
    tree.ensure_tenant(&tid("spin"), 3, &bigger).unwrap();
    assert_eq!(cpu_max(), "20000 100000", "ensure_tenant must not overwrite a controller-owned cpu.max");
    let specs = [spec("spin", bigger, &spinner)];
    run_cg(&mut m, &specs, 2, &tree);
    assert_eq!(cpu_max(), "30000 100000");
    // Role stop: the tenant cgroup is removed and recreated at the ceiling
    // default; the next tick re-applies the throttle.
    std::fs::remove_dir_all(d.path().join("tenants/s3")).unwrap();
    let fresh = TenantLimits { cpu_ceiling_millicores: 4000, ..bigger };
    tree.ensure_tenant(&tid("spin"), 3, &fresh).unwrap();
    assert_eq!(cpu_max(), "400000 100000");
    run_cg(&mut m, &specs, 1, &tree);
    assert_eq!(cpu_max(), "30000 100000", "throttle re-applied after the cgroup was recreated");
    let mut spinner = spinner;
    let _ = spinner.kill();
    let _ = spinner.wait();
}

fn run_cg(m: &mut Monitor, specs: &[TenantSpec], ticks: usize, cg: &nanosiem_lake_cell::limits::CgroupTree) {
    for _ in 0..ticks {
        std::thread::sleep(Duration::from_millis(200));
        m.tick(specs, Some(cg));
    }
}

/// Watchdog mode's cell-wide task ceiling: over it, the tenant furthest
/// over its pids share is killed whole; a tenant within its share never.
#[test]
fn cell_task_ceiling_kills_the_tenant_furthest_over_its_share() {
    let mut bomb = Command::new("sh");
    bomb.args(["-c", "i=0; while [ $i -lt 60 ]; do sleep 60 & i=$((i+1)); done; wait"]).process_group(0);
    let mut bomb = bomb.spawn().unwrap();
    let calm = spawn("mem:1");
    let t0 = Instant::now();
    while procfs::scan().iter().filter(|p| p.stat.ppid == bomb.id()).count() < 60 {
        assert!(t0.elapsed() < Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(50));
    }
    let small = TenantLimits { max_pids: 10, ..limits(50, 500, 64 * MIB, 1 << 40, 1 << 41) };
    let specs = [
        TenantSpec { tenant: tid("bomb"), limits: small, roots: vec![key_of(bomb.id())], uids: vec![], exempt: vec![], unthrottled_uids: vec![] },
        // calm (a libtest process: a few threads) is within its 512.
        spec("calm", limits(50, 500, 64 * MIB, 1 << 40, 1 << 41), &calm),
    ];
    let mut m = Monitor::new(cfg(), huge(), false);
    m.set_pids_ceiling(Some(40));
    let out = run(&mut m, &specs, 1, Duration::from_millis(50));
    assert!(m.pids_saturated());
    assert_eq!(out[0].kill_tenants, vec![(tid("bomb"), KillReason::CellPidsCeiling)]);
    let ev = out[0].events.iter().find(|e| e.kind == EventKind::Killed).unwrap();
    assert_eq!((ev.reason.as_str(), ev.unit, ev.limit), ("cell_pids_ceiling", "tasks", 10.0));
    assert!(ev.observed >= 61.0);
    // SAFETY: kill the bomb's whole group.
    unsafe { libc::kill(-(bomb.id() as i32), libc::SIGKILL) };
    let _ = bomb.wait();
    assert!(calm_alive(&calm));
    let mut calm = calm;
    let _ = calm.kill();
    let _ = calm.wait();
}
