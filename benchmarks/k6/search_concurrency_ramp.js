/**
 * NanoSIEM Search Concurrency Ramp (k6)
 *
 * Steps concurrent virtual users 5 → 10 → 25 → 50 → 100 (discrete stages),
 * driving the realistic IR/SOC corpus (soc_ir_corpus.json) at each query's
 * own analyst window. Finds the concurrency "knee" — the analyst count where
 * p95 blows up, throughput plateaus, or errors climb.
 *
 * Captures BOTH server-side ClickHouse time (execution_time_ms) and client
 * round-trip, per stage, so a true search/CH saturation point is separable
 * from client / port-forward saturation: if server p95 stays flat while
 * round-trip balloons, the bottleneck is the transport, not the engine.
 *
 * NOTE: kubectl port-forward pins to ONE search replica (of 4) and is itself a
 * single TCP proxy. Treat results as PER-REPLICA and watch the server-vs-rt
 * split — cluster capacity is roughly Nx the per-replica knee.
 *
 * Usage:
 *   SEARCH_URL=http://localhost:13002 JWT_TOKEN=$(/tmp/nano_login.sh) \
 *     k6 run benchmarks/k6/search_concurrency_ramp.js
 *
 * Env: SEARCH_URL, API_KEY or JWT_TOKEN, STAGE_SECONDS (default 45)
 */

import http from "k6/http";
import { check, sleep } from "k6";
import exec from "k6/execution";
import { Counter, Rate, Trend } from "k6/metrics";

const SEARCH_URL = __ENV.SEARCH_URL || "http://localhost:3002";
const API_KEY = __ENV.API_KEY || "";
const JWT_TOKEN = __ENV.JWT_TOKEN || "";
const STAGE_SECONDS = parseInt(__ENV.STAGE_SECONDS || "45", 10);

const CORPUS = JSON.parse(open("../results/soc_ir_corpus.json"));
const QUERIES = CORPUS.domains.flatMap((d) => d.queries);

const WINDOW_MS = { "15m": 900000, "1h": 3600000, "6h": 21600000, "24h": 86400000, "7d": 604800000 };
const LEVELS = [5, 10, 25, 50, 100];

// Per-level metrics
const srv = {}, rt = {}, err = {}, reqs = {};
for (const L of LEVELS) {
  srv[L] = new Trend(`lvl${L}_server_ms`, true);
  rt[L] = new Trend(`lvl${L}_rt_ms`, true);
  err[L] = new Rate(`lvl${L}_err`);
  reqs[L] = new Counter(`lvl${L}_reqs`);
}

// One discrete constant-vus scenario per level, run back-to-back with a drain gap.
const scenarios = {};
LEVELS.forEach((L, i) => {
  scenarios[`c${L}`] = {
    executor: "constant-vus",
    vus: L,
    duration: `${STAGE_SECONDS}s`,
    startTime: `${i * (STAGE_SECONDS + 15)}s`,
    tags: { level: String(L) },
    exec: "runStage",
  };
});

export const options = {
  scenarios,
  // No aborting thresholds — we WANT to push past the knee and observe it.
  thresholds: { lvl5_err: ["rate<0.5"] },
};

function authHeaders() {
  const h = { "Content-Type": "application/json" };
  if (JWT_TOKEN) h["Authorization"] = `Bearer ${JWT_TOKEN}`;
  if (API_KEY) h["X-API-Key"] = API_KEY;
  return h;
}

function timeRangeFor(win) {
  const ms = WINDOW_MS[win] || WINDOW_MS["6h"];
  const end = new Date();
  return { start: new Date(end.getTime() - ms).toISOString(), end: end.toISOString() };
}

export function runStage() {
  const L = parseInt(exec.scenario.name.slice(1), 10);
  const q = QUERIES[Math.floor(Math.random() * QUERIES.length)];

  const res = http.post(
    `${SEARCH_URL}/api/search`,
    JSON.stringify({
      query: q.query,
      time_range: timeRangeFor(q.window),
      limit: 200,
      skip_field_stats: true,
      table_view: true,
      request_id: `bench-ramp-${L}-${Date.now()}`,
    }),
    { headers: authHeaders(), tags: { level: String(L) } }
  );

  const ok = check(res, { "status 200": (r) => r.status === 200 });
  let serverMs = null;
  if (res.status === 200 && res.body) {
    try { serverMs = JSON.parse(res.body).execution_time_ms; } catch { /* large body */ }
  }

  reqs[L].add(1);
  err[L].add(!ok);
  rt[L].add(res.timings.duration);
  if (serverMs != null) srv[L].add(serverMs);

  // light think-time so VUs model active analysts but still sustain pressure
  sleep(0.3 + Math.random() * 0.4);
}

export function handleSummary(data) {
  function g(name, key) {
    const m = data.metrics[name];
    if (!m || m.values[key] == null) return "-";
    return m.values[key].toFixed(0);
  }
  function rate(name) {
    const m = data.metrics[name];
    return m ? (m.values.rate * 100).toFixed(2) : "-";
  }
  function count(name) {
    const m = data.metrics[name];
    return m ? m.values.count : 0;
  }

  let rows = "";
  const out = { stages: [] };
  for (const L of LEVELS) {
    const n = count(`lvl${L}_reqs`);
    const thru = (n / STAGE_SECONDS).toFixed(1);
    const sP50 = g(`lvl${L}_server_ms`, "med"), sP95 = g(`lvl${L}_server_ms`, "p(95)"), sP99 = g(`lvl${L}_server_ms`, "p(99)");
    const rP50 = g(`lvl${L}_rt_ms`, "med"), rP95 = g(`lvl${L}_rt_ms`, "p(95)");
    const e = rate(`lvl${L}_err`);
    rows += `║ ${String(L).padStart(4)}  ${String(n).padStart(6)} ${thru.padStart(7)}  │ ${sP50.padStart(6)} ${sP95.padStart(7)} ${sP99.padStart(7)}  │ ${rP50.padStart(6)} ${rP95.padStart(7)}  │ ${e.padStart(6)}% ║\n`;
    out.stages.push({
      vus: L, reqs: n, throughput_rps: parseFloat(thru),
      server_ms: { p50: +sP50 || null, p95: +sP95 || null, p99: +sP99 || null },
      round_trip_ms: { p50: +rP50 || null, p95: +rP95 || null },
      error_rate: parseFloat(e) / 100,
    });
  }

  const summary = `
╔══════════════════════════════════════════════════════════════════════════════╗
║                  SEARCH CONCURRENCY RAMP — per-replica knee                   ║
║        realistic corpus (${String(QUERIES.length).padStart(3)} queries) · ${STAGE_SECONDS}s per stage · server vs round-trip       ║
╠═══════════════════════════════╤══════════════════════════╤═══════════════════╣
║  VUs    reqs   req/s          │  server p50/p95/p99 (ms)  │  rt p50/p95 (ms)  ║  err
╠═══════════════════════════════╪══════════════════════════╪═══════════════════╣
${rows}╚═══════════════════════════════╧══════════════════════════╧═══════════════════╝
 Read: server climbing  = ClickHouse/search saturation (true knee).
       rt climbing while server flat = client / port-forward transport limit.
`;
  console.log(summary);

  return {
    "benchmarks/results/search_concurrency_ramp.json": JSON.stringify(
      { timestamp: new Date().toISOString(), test: "search_concurrency_ramp", stage_seconds: STAGE_SECONDS, corpus_queries: QUERIES.length, levels: LEVELS, stages: out.stages, config: { search_url: SEARCH_URL } },
      null, 2
    ),
    stdout: summary,
  };
}
