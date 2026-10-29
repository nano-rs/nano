# Open-core startup memory sizing

The v1.0.15 renderer gave every standard host shape less memory than the connector runner's 2,048 MiB four-worker startup guard. The generated overlay now derives its worker count from its container limit, reserves startup minima, and budgets only the selected ingest agent.

Each service minimum is `ceil_MiB(max(guard, 1.25 × measured_peak))`. Compose receives `max(45% of host RAM, sum of active service minima)`. Landing replaces its old 1,024 MiB floor with `landing_budget::memory_for_lanes(fitted_lanes)`: 1,152 MiB for one lane, 2,240 for two, 4,416 for four. Up to one third of the pool funds whole CPU/memory-fitted lanes after all sibling minima are paid; remaining memory is shared by the other services' weights. The landing floor is counted once.

The cell takes the remainder of the 95% envelope; 5% stays outside containers. The installer and compiled initializer share `config/lean-startup-memory.json`. The supported host minimum stays **8 GiB**, or the first higher whole-GiB shape required by startup math. Unsupported upgrades stop before checkout/configuration/placement changes. No operator sizing setting was added.

## Measurements

On 2026-10-29 the isolated lab ran digest-verified v1.0.15 open-core images on a 4-CPU, approximately 15 GiB host with memory caps lifted. The installer completed and HEC accepted 12,000 synthetic events in 60.6 seconds. The policy uses the maximum recorded cgroup `memory.peak` over the **full uncapped capture, 18:13:10–18:32:00 UTC**, including later growth beyond the initial summary snapshot. The policy records the raw log's SHA-256 (`fdefc90dae90b72e806a55ebca3bc14b9b9ec7f69273fe1a5c63527b96d317ed`). Idle RSS values remain the separate initial idle snapshot.

The lab then applied the preliminary Vector 8 GiB plan (36 EPS, 1,024 MiB landing, before the landing integration). All 19 runtime containers stayed running with zero restarts and no OOM kills while another 12,000 HEC events were accepted in 60.5 seconds. Authenticated search returned HTTP 200, five rows and total_count 24,002. This validates that preliminary container envelope on a larger physical host; **the final integrated 72/99-EPS plans have not had a physical 8 GiB soak**.

The released runner image separately passed its actual startup guard and sandbox self-test at 704/825 MiB with one worker, then stopped at the deliberately missing database setting. Final renderer/guard tests cover the integrated plans. Landing's production conversion and overlap regressions exercise its shared memory model.

The pinned Tenzir image hit SIGILL on the older lab CPU. The same pinned image on a newer-CPU farm VM accepted 10,600 synthetic HTTP records and measured 160,628,736 peak cgroup bytes. Separate idle RSS was not captured; peak process RSS is shown instead.

Peak means charged cgroup memory, including charged file cache. RSS sums process VmRSS and can count shared pages repeatedly, especially PostgreSQL buffers and common native libraries. These startup/short-ingest measurements do not certify sustained throughput. EPS comes from the existing tenant memory curve.

| Service | Peak MiB | Idle RSS MiB | Guard/floor MiB | Minimum MiB | 8 GiB Vector | 8 GiB Tenzir-direct |
|---|---:|---:|---:|---:|---:|---:|
| connector-runner | 5.6 | 12.2 | 704 | 704 | 704 | — |
| dragonfly | 13.3 | 23.5 | 427 | 427 | 427 | 427 |
| lake-object-store | 118.5 | 176.5 | 0 | 149 | 149 | 149 |
| lean-audit | 4.7 | 9.0 | 0 | 6 | 6 | 6 |
| lean-audit-vector | 13.6 | 64.6 | 0 | 17 | 17 | 17 |
| lean-enrichment | 4.5 | 14.1 | 0 | 6 | 6 | 6 |
| lean-job-runner | 4.7 | 14.2 | 0 | 6 | 6 | 6 |
| lean-landing | 6.1 | 24.7 | 1152 | 1152 | 1152 | 1152 |
| lean-otel | 61.8 | 207.4 | 512 | 512 | 512 | 512 |
| lean-platform-feeds | 53.0 | 7.4 | 0 | 67 | 67 | 67 |
| lean-result-gc | 4.1 | 11.4 | 0 | 6 | 6 | 6 |
| nano-api | 78.8 | 123.8 | 0 | 99 | 99 | 99 |
| nano-jobs | 102.1 | 80.4 | 1024 | 1024 | 1024 | 1024 |
| nano-search | 15.7 | 35.8 | 0 | 20 | 20 | 20 |
| nano-web | 4.4 | 8.8 | 0 | 6 | 6 | 6 |
| nginx | 10.2 | 21.7 | 0 | 13 | 13 | 13 |
| postgres | 200.2 | 546.0 | 0 | 251 | 251 | 251 |
| tenzir | 153.2 | 297.2 peak | 0 | 192 | — | 192 |
| vector | 113.5 | 159.0 | 0 | 142 | 142 | — |

Known guards/floors: runner 256 MiB worker address space + 192 MiB call I/O + 256 MiB reserve = 704 MiB; Dragonfly 256 MiB per thread at 60% maxmemory requires a 427 MiB container; jobs retains its 1 GiB clean-start OOM floor; OTel retains its 512 MiB native allowance. Landing uses the shared maximum-object conversion model, including its process reserve.

## 8 GiB allocation

| Plan | Active Compose | Cell | Planning EPS |
|---|---:|---:|---:|
| Vector and connector | 4,607 MiB | 3,175 MiB | 72 |
| Tenzir-direct, without Vector/connector | 3,953 MiB | 3,829 MiB | 99 |

Both total 7,782 MiB, within 95% of 8 GiB (7,782.4 MiB). Tenzir-direct reserves the optional local Tenzir node; its user-authored pipeline remains opt-in. Re-running the installer removes the excluded local agent before service startup and refuses to proceed if removal fails.

The small-cell plan selects the highest integer EPS whose complete active role allowances fit `TenantBudget::from_eps`. Its 20-EPS minimum is **2,061 MiB**: 205 ingest + 512 query + 256 detect + 512 product + 512 maintenance + 64 supervisor. Active Compose startup minima are 4,607 MiB (Vector) and 3,953 MiB (Tenzir-direct).

The stale 1,024 MiB native landing reservation has been removed from `cell_mib` and from the cell pool subtraction. The generated cell explicitly has `tenzir_landing=false` and placement `landing=false`. A valid dormant role-budget template remains in placement for the existing schema; the supervisor does not add it to tenant memory. Compose's separate `lean-landing` container owns all funded landing capacity. Production-path tests check the supervisor's active-role accounting.

| Active cell allowance | Vector MiB | Tenzir-direct MiB |
|---|---:|---:|
| Ingest | 662 | 899 |
| Query | 1,158 | 1,573 |
| Detect | 256 | 256 |
| Product | 512 | 512 |
| Maintenance | 512 | 512 |
| Supervisor | 64 | 64 |
| Additional slack | 11 | 13 |

The next integer EPS does not fit either small plan. Excess explicit small-cell targets and whole-host-overcommitting overrides are refused before placement writes. Cells of at least 4 GiB retain the existing larger-host role-sizing path with the inactive landing reservation removed. `x-nano-host-sizing.supported_eps` and installer output report the planned rate.

## Capacity and resizing

| Host GiB / CPUs | Ingest path | Compose MiB | Cell MiB | Planning EPS | Landing MiB / lanes |
|---|---|---:|---:|---:|---:|
| 8 / 4 | Vector | 4,607 | 3,175 | 72 | 1,152 / 1 |
| 8 / 4 | Tenzir-direct | 3,953 | 3,829 | 99 | 1,152 / 1 |
| 16 / 8 | Vector | 7,368 | 8,192 | 630 | 2,240 / 2 |
| 16 / 8 | Tenzir-direct | 7,366 | 8,192 | 630 | 2,240 / 2 |
| 32 / 16 | Vector | 14,738 | 16,384 | 1,100 | 4,416 / 4 |
| 32 / 16 | Tenzir-direct | 14,740 | 16,384 | 1,100 | 4,416 / 4 |
| 64 / 32 | Vector | 29,482 | 32,768 | 3,970 | 8,768 / 8 |
| 64 / 32 | Tenzir-direct | 29,482 | 32,768 | 3,970 | 8,768 / 8 |
| 128 / 64 | Vector | 58,971 | 65,536 | 9,380 | 19,648 / 18 |
| 128 / 64 | Tenzir-direct | 58,972 | 65,536 | 9,380 | 19,648 / 18 |

Sizing is recomputed on every ordinary install/upgrade. The installer re-reads Docker memory for preflight. The one-shot initializer re-reads Docker-visible `/proc/meminfo` MemTotal and the online CPU set, then re-renders placement and `compose.resources.json`. The installer replaces the generated resource overlay and starts/recreates services with it. A grown host adopts its new memory/CPU plan; sizing is not fixed at first install. Ordinary install passes neither standalone memory nor CPU overrides. The production-path resize regression changes host facts from 8 to 16 GiB, checks both ingest choices, and verifies increased placement/container budgets with the same identity and tokens.

## Temporary runner workaround for v1.0.15

Create `connector-runner-memory-workaround.yml`:

```yaml
services:
  connector-runner:
    mem_limit: 704m
    memswap_limit: 704m
    deploy:
      resources:
        limits:
          memory: 704m
    environment:
      CONNECTOR_VRL_MAX_WORKERS: "1"
      CONNECTOR_VRL_WORKER_AS_BYTES: "268435456"
```

Load it after the generated resource overlay (and any installed sovereign/TLS overlays):

```sh
docker compose -f docker-compose.opensource.yml \
  -f docker-compose.host-resources.yml \
  -f connector-runner-memory-workaround.yml up -d --no-deps connector-runner
```

This unblocks the runner guard only and needs 704 MiB available for that container. Upgrade to the corrected release for whole-host accounting and the other service minima. Re-running the v1.0.15 initializer alone recreates its bad limits.
