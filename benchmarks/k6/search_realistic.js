/**
 * NanoSIEM Realistic IR/SOC Search Benchmark (k6)
 *
 * Replays a corpus of REAL, source-scoped IR/SOC investigations — each at the
 * time window an analyst would actually use (triage 15m-1h, hunt 6-24h, retro
 * IR 24h-7d). This is the realistic counterpart to search.js, whose bare-keyword
 * /24h queries are a deliberate worst-case stress probe.
 *
 * The query corpus is the source of truth: benchmarks/results/soc_ir_corpus.json
 * (each entry: {use_case, tier, mitre, query, window, catches}). Edit that file
 * to change what runs — this script picks it up automatically.
 *
 * Usage:
 *   SEARCH_URL=http://localhost:13002 JWT_TOKEN=$(/tmp/nano_login.sh) \
 *     k6 run benchmarks/k6/search_realistic.js
 *
 * Env: SEARCH_URL (default http://localhost:3002), API_KEY or JWT_TOKEN, VUS (default 3), DURATION (default 3m)
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

const SEARCH_URL = __ENV.SEARCH_URL || "http://localhost:3002";
const API_KEY = __ENV.API_KEY || "";
const JWT_TOKEN = __ENV.JWT_TOKEN || "";
const VUS = parseInt(__ENV.VUS || "3", 10);
const DURATION = __ENV.DURATION || "3m";

// --- Corpus (read at init) ---
const CORPUS = JSON.parse(open("../results/soc_ir_corpus.json"));
const QUERIES = CORPUS.domains.flatMap((d) =>
  d.queries.map((q) => ({ ...q, domain: d.domain }))
);

const WINDOW_MS = {
  "15m": 900000,
  "1h": 3600000,
  "6h": 21600000,
  "24h": 86400000,
  "7d": 604800000,
};

// --- Metrics ---
const overallRt = new Trend("query_latency_ms", true);
const overallSrv = new Trend("server_latency_ms", true);
const queryErrors = new Rate("query_error_rate");
const queriesExecuted = new Counter("queries_executed");

const TIERS = ["triage", "hunt", "ir"];
const tierSrv = {};
const tierRt = {};
for (const t of TIERS) {
  tierSrv[t] = new Trend(`tier_${t}_server_ms`, true);
  tierRt[t] = new Trend(`tier_${t}_rt_ms`, true);
}

// Per-domain trends (sanitized keys → display names for the summary)
const DOMAINS = [...new Set(QUERIES.map((q) => q.domain))];
const domKey = {};
const domSrv = {};
DOMAINS.forEach((d, i) => {
  const key = `dom_${i}`;
  domKey[d] = key;
  domSrv[key] = new Trend(`${key}_server_ms`, true);
});

export const options = {
  scenarios: {
    realistic: { executor: "constant-vus", vus: VUS, duration: DURATION },
  },
  thresholds: {
    tier_triage_server_ms: ["p(95)<1000"],
    tier_hunt_server_ms: ["p(95)<2000"],
    tier_ir_server_ms: ["p(95)<5000"],
    query_error_rate: ["rate<0.05"],
  },
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
  return {
    start: new Date(end.getTime() - ms).toISOString(),
    end: end.toISOString(),
  };
}

function serverTime(res) {
  if (res.status !== 200 || !res.body) return null;
  try {
    const b = JSON.parse(res.body);
    return b.execution_time_ms != null ? b.execution_time_ms : null;
  } catch {
    return null;
  }
}

export default function () {
  const headers = authHeaders();

  for (const q of QUERIES) {
    group(q.use_case, function () {
      const payload = JSON.stringify({
        query: q.query,
        time_range: timeRangeFor(q.window),
        limit: 200,
        skip_field_stats: true,
        table_view: true,
        request_id: `bench-real-${q.tier}-${Date.now()}`,
      });

      const res = http.post(`${SEARCH_URL}/api/search`, payload, {
        headers,
        tags: { tier: q.tier, window: q.window, name: q.use_case },
      });

      const ok = check(res, { "status 200": (r) => r.status === 200 }, { tier: q.tier });

      const srv = serverTime(res);
      const rt = res.timings.duration;

      queriesExecuted.add(1);
      queryErrors.add(!ok);
      overallRt.add(rt);
      if (srv != null) overallSrv.add(srv);

      if (tierRt[q.tier]) tierRt[q.tier].add(rt);
      if (srv != null && tierSrv[q.tier]) tierSrv[q.tier].add(srv);
      if (srv != null && domSrv[domKey[q.domain]]) domSrv[domKey[q.domain]].add(srv);
    });

    sleep(0.2);
  }
}

export function handleSummary(data) {
  const dur = data.state.testRunDurationMs / 1000;
  const total = data.metrics.queries_executed
    ? data.metrics.queries_executed.values.count
    : 0;
  const err = data.metrics.query_error_rate
    ? data.metrics.query_error_rate.values.rate
    : 0;

  function p(metric, key) {
    if (!metric) return "-";
    const v = metric.values[key];
    return v != null ? v.toFixed(0) : "-";
  }
  function line(label, m) {
    return `  ${label.padEnd(34)} ${p(m, "med").padStart(7)}ms ${p(m, "p(95)").padStart(7)}ms ${p(m, "max").padStart(7)}ms`;
  }

  let tierLines = "";
  for (const t of TIERS) {
    tierLines += line(`Tier: ${t}`, data.metrics[`tier_${t}_server_ms`]) + "\n";
  }
  let domLines = "";
  for (const d of DOMAINS) {
    domLines += line(d.slice(0, 33), data.metrics[`${domKey[d]}_server_ms`]) + "\n";
  }

  const summary = `
╔════════════════════════════════════════════════════════════════════╗
║         REALISTIC IR/SOC SEARCH BENCHMARK (server-side CH)          ║
╠════════════════════════════════════════════════════════════════════╣
║  Corpus queries:  ${String(QUERIES.length).padStart(5)}   VUs: ${String(VUS).padStart(2)}   Duration: ${dur.toFixed(0).padStart(4)}s          ║
║  Total executed:  ${String(total).padStart(5)}        Error rate: ${(err * 100).toFixed(2).padStart(6)}%        ║
╠════════════════════════════════════════════════════════════════════╣
║  By tier                              p50      p95      max         ║
╠════════════════════════════════════════════════════════════════════╣
${tierLines}╠════════════════════════════════════════════════════════════════════╣
║  By domain                            p50      p95      max         ║
╠════════════════════════════════════════════════════════════════════╣
${domLines}╚════════════════════════════════════════════════════════════════════╝
`;
  console.log(summary);

  function ex(m) {
    if (!m) return null;
    return {
      p50_ms: Math.round(m.values.med || 0),
      p95_ms: Math.round(m.values["p(95)"] || 0),
      max_ms: Math.round(m.values.max || 0),
      avg_ms: Math.round(m.values.avg || 0),
    };
  }
  const byTier = {};
  for (const t of TIERS) byTier[t] = ex(data.metrics[`tier_${t}_server_ms`]);
  const byDomain = {};
  for (const d of DOMAINS) byDomain[d] = ex(data.metrics[`${domKey[d]}_server_ms`]);

  return {
    "benchmarks/results/search_realistic.json": JSON.stringify(
      {
        timestamp: new Date().toISOString(),
        test: "search_realistic",
        corpus_queries: QUERIES.length,
        total_executed: total,
        error_rate: err,
        overall: { server: ex(data.metrics.server_latency_ms), round_trip: ex(data.metrics.query_latency_ms) },
        by_tier: byTier,
        by_domain: byDomain,
        config: { search_url: SEARCH_URL, vus: VUS, duration: DURATION },
      },
      null,
      2
    ),
    stdout: summary,
  };
}
