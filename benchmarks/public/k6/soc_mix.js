/**
 * nano public benchmark: the "normal SOC day" query mix (k6).
 *
 * Three concurrent populations, all against one install, while log-blaster
 * holds steady ingest and the detection set runs:
 *
 *   analysts   replay the IR/SOC corpus (benchmarks/results/soc_ir_corpus.json):
 *              real, source-scoped hunts at the window an analyst would use
 *              (triage 15m-1h, hunt 6-24h, retro IR 24h-7d), with think time.
 *   dashboards refresh the SOC overview panels (dashboards/soc-overview.json)
 *              every REFRESH_SECS, bypassing the panel cache.
 *   agents     Agent Lane agents hunting in native ClickHouse SQL with the
 *              recipes the agent kit ships (skills/nano-agentlane/references/
 *              recipes.sql). Enabled only when NAL_TOKENS_FILE is set.
 *
 * Env:
 *   APP_URL          app host base URL (nginx :80), e.g. http://10.0.0.11
 *   API_KEY          search API key (X-API-Key)
 *   ANALYSTS         analyst VUs (default 5)
 *   DASHBOARDS       dashboard viewers (default 3)
 *   REFRESH_SECS     dashboard refresh interval (default 60)
 *   AGENTS           Agent Lane agents (default 0; 2-3 for the published run)
 *   NAL_TOKENS_FILE  JSON list [{username,password,url}] from setup_content.py;
 *                    each agent gets its own token (mint at least AGENTS)
 *   AGENT_THINK_MIN / AGENT_THINK_MAX  seconds between an agent's queries
 *                    (default 6-12 s: an LLM agent's turn, and under Agent
 *                    Lane's default per-token quota of 600 queries an hour)
 *   NAL_TABLE_SUFFIX "" on a single ClickHouse node, "_distributed" on a cluster
 *   DURATION         e.g. 10m (default), RESULTS_FILE (default soc_mix.json)
 *
 * Output: RESULTS_FILE with p50/p95/p99 per query class (tier for analysts,
 * panel for dashboards, recipe for agents), error rates and counts.
 */

import http from "k6/http";
import encoding from "k6/encoding";
import { sleep } from "k6";
import exec from "k6/execution";
import { Counter, Rate, Trend } from "k6/metrics";

const APP_URL = (__ENV.APP_URL || "http://localhost").replace(/\/$/, "");
const API_KEY = __ENV.API_KEY || "";
const ANALYSTS = parseInt(__ENV.ANALYSTS || "5", 10);
const DASHBOARDS = parseInt(__ENV.DASHBOARDS || "3", 10);
const REFRESH_SECS = parseInt(__ENV.REFRESH_SECS || "60", 10);
const AGENTS = parseInt(__ENV.AGENTS || "0", 10);
const DURATION = __ENV.DURATION || "10m";
const RESULTS_FILE = __ENV.RESULTS_FILE || "soc_mix.json";
const SUFFIX = __ENV.NAL_TABLE_SUFFIX || "";
const AGENT_THINK_MIN = parseFloat(__ENV.AGENT_THINK_MIN || "6");
const AGENT_THINK_MAX = parseFloat(__ENV.AGENT_THINK_MAX || "12");

// --- inputs (read at init) ---------------------------------------------------
const CORPUS = JSON.parse(open("../../results/soc_ir_corpus.json"));
const QUERIES = CORPUS.domains.flatMap((d) => d.queries.map((q) => ({ ...q, domain: d.key })));
const PANELS = JSON.parse(open("../dashboards/soc-overview.json")).panels;
const RECIPES = AGENTS > 0 ? parseRecipes(open("../../../skills/nano-agentlane/references/recipes.sql")) : [];
const LANE = AGENTS > 0 && __ENV.NAL_TOKENS_FILE ? JSON.parse(open(__ENV.NAL_TOKENS_FILE)) : [];

const WINDOW_MS = { "15m": 9e5, "1h": 36e5, "6h": 216e5, "24h": 864e5, "7d": 6048e5 };
const TIERS = ["triage", "hunt", "ir"];

// --- metrics -----------------------------------------------------------------
const trends = {};
function trend(name) {
  if (!trends[name]) trends[name] = new Trend(name, true);
  return trends[name];
}
for (const t of TIERS) {
  trend(`search_${t}_server_ms`);
  trend(`search_${t}_rt_ms`);
}
trend("dashboard_panel_rt_ms");
trend("agent_query_rt_ms");
const errors = {
  analysts: new Rate("analyst_error_rate"),
  dashboards: new Rate("dashboard_error_rate"),
  agents: new Rate("agent_error_rate"),
};
const executed = new Counter("queries_executed");

// --- scenarios ---------------------------------------------------------------
const scenarios = {};
if (ANALYSTS > 0) scenarios.analysts = { executor: "constant-vus", vus: ANALYSTS, duration: DURATION, exec: "analyst" };
if (DASHBOARDS > 0) {
  scenarios.dashboards = {
    executor: "constant-arrival-rate",
    rate: DASHBOARDS,
    timeUnit: `${REFRESH_SECS}s`,
    duration: DURATION,
    preAllocatedVUs: Math.max(DASHBOARDS * 2, 2),
    exec: "dashboard",
  };
}
if (AGENTS > 0 && LANE.length > 0 && RECIPES.length > 0) {
  scenarios.agents = { executor: "constant-vus", vus: AGENTS, duration: DURATION, exec: "agent" };
}
export const options = {
  scenarios,
  // Agent Lane uses the install's private CA; k6 has no per-host CA option.
  insecureSkipTLSVerify: AGENTS > 0,
  summaryTrendStats: ["avg", "med", "p(95)", "p(99)", "max", "count"],
};

function apiHeaders() {
  return { "Content-Type": "application/json", "X-API-Key": API_KEY };
}

function range(window) {
  const end = Date.now();
  return { start: new Date(end - (WINDOW_MS[window] || 36e5)).toISOString(), end: new Date(end).toISOString() };
}

export function analyst() {
  const q = QUERIES[Math.floor(Math.random() * QUERIES.length)];
  const t0 = Date.now();
  const res = http.post(
    `${APP_URL}/api/search`,
    JSON.stringify({ query: q.query, time_range: range(q.window), limit: 200, skip_field_stats: true, table_view: true }),
    { headers: apiHeaders(), timeout: "120s", tags: { kind: "analyst", tier: q.tier, domain: q.domain } }
  );
  const rt = Date.now() - t0;
  const ok = res.status === 200;
  errors.analysts.add(!ok, { tier: q.tier });
  executed.add(1, { kind: "analyst" });
  if (ok) {
    let srv = rt;
    try {
      const body = res.json();
      if (body && typeof body.execution_time_ms === "number") srv = body.execution_time_ms;
    } catch (_) {}
    trend(`search_${q.tier}_server_ms`).add(srv);
    trend(`search_${q.tier}_rt_ms`).add(rt);
  }
  // Analyst think time: read the results, pivot, write notes.
  sleep(5 + Math.random() * 15);
}

export function dashboard() {
  // One refresh = every panel of the overview, as the UI fires them.
  const reqs = PANELS.map((p) => [
    "POST",
    `${APP_URL}/api/dashboards/panel/query`,
    JSON.stringify({ query: p.query, query_mode: "piped", time_range: range(p.window || "24h"), bypass_cache: true }),
    { headers: apiHeaders(), timeout: "120s", tags: { kind: "dashboard", panel: p.id } },
  ]);
  const t0 = Date.now();
  const res = http.batch(reqs);
  const rt = Date.now() - t0;
  let bad = 0;
  res.forEach((r) => {
    if (r.status !== 200) bad += 1;
  });
  errors.dashboards.add(bad > 0);
  executed.add(res.length, { kind: "dashboard" });
  trend("dashboard_panel_rt_ms").add(rt);
}

// One token per agent. __VU is global across scenarios, so (__VU - 1) % n can
// give two agents the same token; take the scenario-local order of each VU's
// first iteration instead (0..AGENTS-1 for a constant-vus scenario).
let agentTok = null;
export function agent() {
  if (agentTok === null) agentTok = LANE[exec.scenario.iterationInTest % LANE.length];
  const tok = agentTok;
  const r = RECIPES[Math.floor(Math.random() * RECIPES.length)];
  const params = Object.entries(r.params)
    .map(([k, v]) => `param_${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
  const url = `${tok.url.replace(/\/$/, "")}/?log_comment=nano-benchmark-agent-${__VU}${params ? "&" + params : ""}`;
  const sql = SUFFIX ? r.sql.replace(/nanosiem\.([a-z_0-9]+)\b(?!_distributed)/g, `nanosiem.$1${SUFFIX}`) : r.sql;
  const t0 = Date.now();
  const res = http.post(url, sql, {
    headers: { Authorization: `Basic ${encoding.b64encode(`${tok.username}:${tok.password}`)}` },
    timeout: "90s",
    tags: { kind: "agent", recipe: r.id },
  });
  const rt = Date.now() - t0;
  errors.agents.add(res.status !== 200, { recipe: r.id });
  executed.add(1, { kind: "agent" });
  if (res.status === 200) trend("agent_query_rt_ms").add(rt);
  // An agent reads the rows and decides its next query.
  sleep(AGENT_THINK_MIN + Math.random() * (AGENT_THINK_MAX - AGENT_THINK_MIN));
}

// Recipes: `-- @recipe <id>` blocks; `-- @param <name> <Type> <example>`
// lines give the bound example values (the kit's own check uses them too).
function parseRecipes(text) {
  const out = [];
  let cur = null;
  for (const line of text.split("\n")) {
    const m = line.match(/^-- @recipe\s+(\S+)/);
    if (m) {
      if (cur) out.push(cur);
      cur = { id: m[1], params: {}, sql: "" };
      continue;
    }
    if (!cur) continue;
    const p = line.match(/^-- @param\s+(\S+)\s+(\S+(?:\([^)]*\))?)\s+(.+)$/);
    if (p) {
      cur.params[p[1]] = p[3].trim();
      continue;
    }
    if (line.startsWith("--")) continue;
    cur.sql += line + "\n";
  }
  if (cur) out.push(cur);
  // `system.*` discovery recipes are not hunts; skip them for load.
  return out
    .map((r) => ({ ...r, sql: r.sql.trim().replace(/;\s*$/, "") }))
    .filter((r) => r.sql && !/FROM\s+system\./i.test(r.sql));
}

// --- summary -> JSON ------------------------------------------------------------
function pick(m) {
  if (!m || !m.values) return null;
  const v = m.values;
  return { count: v.count || 0, p50_ms: v.med, p95_ms: v["p(95)"], p99_ms: v["p(99)"], max_ms: v.max, avg_ms: v.avg };
}

export function handleSummary(data) {
  const m = data.metrics;
  const out = {
    schema: "nano-benchmark/soc-mix@1",
    generated_at: new Date().toISOString(),
    config: { analysts: ANALYSTS, dashboards: DASHBOARDS, refresh_secs: REFRESH_SECS,
              agents: scenarios.agents ? AGENTS : 0, duration: DURATION, corpus_queries: QUERIES.length,
              panels: PANELS.length, recipes: RECIPES.length,
              agent_think_secs: [AGENT_THINK_MIN, AGENT_THINK_MAX], agent_tokens: LANE.length },
    search_by_tier: Object.fromEntries(TIERS.map((t) => [t, {
      server: pick(m[`search_${t}_server_ms`]),
      round_trip: pick(m[`search_${t}_rt_ms`]),
    }])),
    dashboard_refresh: pick(m.dashboard_panel_rt_ms),
    agent_queries: pick(m.agent_query_rt_ms),
    error_rates: {
      analysts: m.analyst_error_rate ? m.analyst_error_rate.values.rate : null,
      dashboards: m.dashboard_error_rate ? m.dashboard_error_rate.values.rate : null,
      agents: m.agent_error_rate ? m.agent_error_rate.values.rate : null,
    },
    queries_executed: m.queries_executed ? m.queries_executed.values.count : 0,
  };
  return { [RESULTS_FILE]: JSON.stringify(out, null, 2), stdout: JSON.stringify(out) + "\n" };
}
