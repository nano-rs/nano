# NanoSIEM Benchmarks

Performance benchmarking suite for measuring ingestion throughput, search latency, and concurrent analyst capacity.

## Prerequisites

- [k6](https://k6.io/docs/get-started/installation/) (`brew install k6`)
- Running nanosiem stack (Vector, ClickHouse, search service)
- API key or JWT token for search benchmarks

## Quick Start

```bash
# Run all benchmarks
./benchmarks/run-benchmark.sh --all --api-key YOUR_API_KEY

# Ingestion only (k6 ramp-up)
./benchmarks/run-benchmark.sh --ingest

# Ingestion with log-blaster (high EPS stress test)
./benchmarks/run-benchmark.sh --ingest --blast --blast-eps 50000 --blast-duration 5

# Search latency across query types
./benchmarks/run-benchmark.sh --search --api-key YOUR_API_KEY --time-range 7d

# Concurrent analyst simulation (10 analysts)
./benchmarks/run-benchmark.sh --concurrent --api-key YOUR_API_KEY --analysts 10
```

## Benchmarks

### Ingestion (`k6/ingestion.js`)

Measures Vector HTTP ingestion throughput using NDJSON batches. Ramps VUs from 1→40 to find the saturation point.

- **Metrics**: EPS, batch latency (p50/p95/p99), error rate
- **Log mix**: 40% Apache, 30% Defender EDR, 30% syslog
- **Batch size**: 100 events per request (configurable via `BATCH_SIZE`)

For sustained high-EPS tests, use `--blast` which runs `log-blaster` in blast mode with realistic multi-source log generation.

### Search (`k6/search.js`)

Measures nPL query latency across five query categories:

| Category | Example | What it tests |
|----------|---------|---------------|
| Simple search | `src_ip="10.1.0.1"` | Index lookup, PREWHERE |
| Stats/aggregation | `\| stats count by src_ip` | GROUP BY, sorting |
| Timechart | `\| timechart span=1h count` | Time bucketing |
| Regex | `command_line=/powershell.*-enc.*/i` | Regex engine load |
| Filter chain | `\| stats count by src_ip \| where count > 100` | Multi-stage pipeline |

Runs 3 concurrent VUs for 90 seconds.

### Concurrent Analysts (`k6/concurrent.js`)

Simulates realistic SOC workflows with 5 analyst personas:

| Persona | Behavior | Think time |
|---------|----------|------------|
| Threat Hunter | Rare process queries, prevalence analysis | 3-8s |
| SOC Analyst L1 | Error triage, status code analysis | 2-5s |
| Incident Responder | IP/host pivoting, timeline queries | 1-4s |
| Dashboard Viewer | Parallel aggregation queries, auto-refresh | 10-30s |
| Detection Engineer | Low-prevalence hunting, threshold analysis | 5-15s |

Each persona runs different nPL queries with realistic think times between actions.

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | *(default)* | Run all benchmarks |
| `--ingest` | | Ingestion benchmark only |
| `--search` | | Search benchmark only |
| `--concurrent` | | Concurrent analyst benchmark only |
| `--blast` | | Use log-blaster instead of k6 for ingestion |
| `--blast-eps NUM` | 10000 | Target EPS for blast mode |
| `--blast-duration M` | 2 | Blast duration in minutes |
| `--time-range` | 24h | Search lookback: 1h, 24h, 7d, 30d |
| `--analysts NUM` | 5 | Number of simulated analysts |
| `--vector-url URL` | http://localhost:8080 | Vector endpoint |
| `--search-url URL` | http://localhost:3002 | Search service endpoint |
| `--api-key KEY` | | API key for auth |
| `--jwt-token TOKEN` | | JWT token for auth |

## Results

Results are saved to `benchmarks/results/` as JSON files:
- `ingestion.json` — EPS, batch latency, error rate
- `search.json` — Per-query-type p50/p95/p99 latency
- `concurrent.json` — Per-action-type latency under load

The runner also queries ClickHouse `system.query_log` for server-side metrics and `system.parts` for storage compression ratios.

## Interpreting Results

**Ingestion targets:**
- Healthy: p95 batch latency < 500ms, error rate < 1%
- At capacity: p95 > 2s or errors climbing — Vector or ClickHouse backpressure

**Search targets:**
- Simple search: p95 < 500ms
- Stats/aggregation: p95 < 2s
- Timechart: p95 < 3s
- Complex filter chains: p95 < 5s

**Concurrent analyst targets:**
- 5 analysts: p95 search < 3s
- 10 analysts: p95 search < 5s
- Dashboard loads: p95 < 5s

These are ballpark targets for a single-node deployment with ~10M events. Adjust expectations based on data volume, hardware, and ClickHouse cluster size.
