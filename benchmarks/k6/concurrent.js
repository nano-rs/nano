/**
 * NanoSIEM Concurrent Analyst Simulation (k6)
 *
 * Simulates multiple SOC analysts working simultaneously:
 * - Running searches with different patterns
 * - Loading dashboards (multiple parallel queries)
 * - Drilling into results (field stats, log detail)
 *
 * Usage:
 *   k6 run benchmarks/k6/concurrent.js
 *
 * Environment variables:
 *   SEARCH_URL   - Search service URL (default: http://localhost:3002)
 *   API_URL      - Main API URL (default: http://localhost:3000)
 *   API_KEY      - API key for auth (required)
 *   JWT_TOKEN    - JWT bearer token (alternative to API_KEY)
 *   ANALYSTS     - Number of simulated analysts (default: 5)
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

const searchLatency = new Trend("analyst_search_latency_ms", true);
const dashboardLatency = new Trend("dashboard_load_latency_ms", true);
const fieldStatsLatency = new Trend("field_stats_latency_ms", true);
const errors = new Rate("analyst_error_rate");
const actions = new Counter("analyst_actions");

const SEARCH_URL = __ENV.SEARCH_URL || "http://localhost:3002";
const API_URL = __ENV.API_URL || "http://localhost:3000";
const API_KEY = __ENV.API_KEY || "";
const JWT_TOKEN = __ENV.JWT_TOKEN || "";
const ANALYSTS = parseInt(__ENV.ANALYSTS || "5", 10);

export const options = {
  scenarios: {
    analysts: {
      executor: "constant-vus",
      vus: ANALYSTS,
      duration: "120s",
    },
  },
  thresholds: {
    analyst_search_latency_ms: ["p(95)<10000"],
    analyst_error_rate: ["rate<0.10"],
  },
};

function authHeaders() {
  const headers = { "Content-Type": "application/json" };
  if (JWT_TOKEN) headers["Authorization"] = `Bearer ${JWT_TOKEN}`;
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  return headers;
}

function timeRange(hoursBack) {
  const now = new Date();
  return {
    start: new Date(now.getTime() - hoursBack * 3600000).toISOString(),
    end: now.toISOString(),
  };
}

// Analyst personas with different query patterns
const PERSONAS = [
  {
    name: "threat_hunter",
    queries: [
      'source_type=windows_sysmon action=process_create | stats count by process_name | sort -count | head 20',
      'command_line=/powershell.*-enc.*/i',
      'source_type=windows_event action=logon_failure | stats count by src_ip, user | where count > 3',
      '| stats count by src_ip | where count > 1000 | sort -count',
    ],
    think_time: [3, 8], // seconds between queries
    time_range_hours: 24,
  },
  {
    name: "soc_analyst_l1",
    queries: [
      "error OR fail OR denied",
      'http_status_code>=400 | stats count by src_ip | sort -count | head 10',
      'source_type=apache_access | timechart span=15m count',
      'source_type=windows_event action=logon_failure | stats count by user | sort -count',
    ],
    think_time: [2, 5],
    time_range_hours: 1,
  },
  {
    name: "incident_responder",
    queries: [
      'src_ip="10.0.0.51" OR dest_ip="10.0.0.51"',
      'user="admin-ops" | stats count by action, source_type',
      'src_ip="10.0.0.51" | timechart span=5m count by action',
      'src_host="ws-exec-087.corp.local" source_type=windows_sysmon',
    ],
    think_time: [1, 4],
    time_range_hours: 72,
  },
  {
    name: "dashboard_viewer",
    queries: [
      "| stats count by source_type",
      "| timechart span=1h count",
      "| stats count by src_ip | sort -count | head 10",
      '| stats dc(user) as unique_users, dc(src_ip) as unique_ips',
    ],
    think_time: [10, 30], // dashboards auto-refresh
    time_range_hours: 24,
  },
  {
    name: "detection_engineer",
    queries: [
      'source_type=windows_sysmon action=process_create command_line=/.*rundll32.*/i',
      '| stats count by process_name, action | where count < 5',
      'source_type=windows_sysmon | stats dc(src_host) as host_count by process_name | where host_count = 1',
      'source_type=windows_event action=logon_failure | stats count by user | where count > 10',
    ],
    think_time: [5, 15],
    time_range_hours: 168, // 7 days
  },
];

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function doSearch(query, hours, headers) {
  const payload = JSON.stringify({
    query: query,
    time_range: timeRange(hours),
    limit: 100,
    skip_field_stats: true,
    table_view: true,
    request_id: `bench-concurrent-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  });

  const res = http.post(`${SEARCH_URL}/api/search`, payload, { headers });

  const ok = check(res, {
    "search 200": (r) => r.status === 200,
  });

  searchLatency.add(res.timings.duration);
  errors.add(!ok);
  actions.add(1);

  return res;
}

function doFieldStats(field, hours, headers) {
  const payload = JSON.stringify({
    field: field,
    time_range: timeRange(hours),
    limit: 20,
  });

  const res = http.post(`${SEARCH_URL}/api/search/field-stats`, payload, { headers });

  check(res, { "field-stats 200": (r) => r.status === 200 });
  fieldStatsLatency.add(res.timings.duration);
  actions.add(1);
}

function doDashboardLoad(headers) {
  // Simulate dashboard: 4 parallel queries
  const queries = [
    "| stats count by source_type",
    "| timechart span=1h count",
    "| stats count by src_ip | sort -count | head 10",
    "| timechart span=1h count by source_type",
  ];

  const tr = timeRange(24);
  const requests = queries.map((q) => ({
    method: "POST",
    url: `${SEARCH_URL}/api/search`,
    body: JSON.stringify({
      query: q,
      time_range: tr,
      limit: 1000,
      skip_field_stats: true,
      request_id: `bench-dash-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    }),
    params: { headers },
  }));

  const responses = http.batch(requests);
  let allOk = true;
  for (const res of responses) {
    if (res.status !== 200) allOk = false;
    dashboardLatency.add(res.timings.duration);
  }
  errors.add(!allOk);
  actions.add(queries.length);
}

// --- Main test function ---

export default function () {
  const persona = PERSONAS[__VU % PERSONAS.length];
  const headers = authHeaders();

  group(`analyst_${persona.name}`, function () {
    // Each iteration: run through the persona's query set
    for (const query of persona.queries) {
      doSearch(query, persona.time_range_hours, headers);

      // Sometimes drill into field stats (30% chance)
      if (Math.random() < 0.3) {
        const fields = ["src_ip", "user", "source_type", "process_name", "action"];
        doFieldStats(
          fields[Math.floor(Math.random() * fields.length)],
          persona.time_range_hours,
          headers
        );
      }

      // Think time between queries
      const [min, max] = persona.think_time;
      sleep(randomInt(min, max));
    }

    // Dashboard viewer also loads dashboards
    if (persona.name === "dashboard_viewer") {
      doDashboardLoad(headers);
    }
  });
}

export function handleSummary(data) {
  const duration = data.state.testRunDurationMs / 1000;
  const totalActions = data.metrics.analyst_actions
    ? data.metrics.analyst_actions.values.count
    : 0;
  const errRate = data.metrics.analyst_error_rate
    ? data.metrics.analyst_error_rate.values.rate
    : 0;

  function pval(v, key) {
    const val = v[key];
    return val != null ? val.toFixed(0) : "-";
  }

  function metricLine(name, metric) {
    if (!metric) return `  ${name.padEnd(22)} -         -         -`;
    const v = metric.values;
    return `  ${name.padEnd(22)} ${pval(v, "med").padStart(8)}ms ${pval(v, "p(95)").padStart(8)}ms ${pval(v, "p(99)").padStart(8)}ms`;
  }

  const summary = `
╔══════════════════════════════════════════════════════════════╗
║         CONCURRENT ANALYST BENCHMARK RESULTS                 ║
╠══════════════════════════════════════════════════════════════╣
║  Duration:        ${duration.toFixed(1).padStart(10)}s                              ║
║  Analysts (VUs):  ${String(ANALYSTS).padStart(10)}                               ║
║  Total Actions:   ${String(totalActions).padStart(10)}                               ║
║  Error Rate:      ${(errRate * 100).toFixed(2).padStart(10)}%                              ║
╠══════════════════════════════════════════════════════════════╣
║  Metric                 p50       p95       p99              ║
╠══════════════════════════════════════════════════════════════╣
${metricLine("Search", data.metrics.analyst_search_latency_ms)}
${metricLine("Dashboard Load", data.metrics.dashboard_load_latency_ms)}
${metricLine("Field Stats", data.metrics.field_stats_latency_ms)}
╚══════════════════════════════════════════════════════════════╝
`;
  console.log(summary);

  return {
    "benchmarks/results/concurrent.json": JSON.stringify(
      {
        timestamp: new Date().toISOString(),
        test: "concurrent_analysts",
        duration_s: duration,
        analyst_count: ANALYSTS,
        total_actions: totalActions,
        error_rate: errRate,
        search: data.metrics.analyst_search_latency_ms
          ? {
              p50_ms: Math.round(data.metrics.analyst_search_latency_ms.values.med || 0),
              p95_ms: Math.round(data.metrics.analyst_search_latency_ms.values["p(95)"] || 0),
              p99_ms: Math.round(data.metrics.analyst_search_latency_ms.values["p(99)"] || 0),
            }
          : null,
        dashboard: data.metrics.dashboard_load_latency_ms
          ? {
              p50_ms: Math.round(data.metrics.dashboard_load_latency_ms.values.med || 0),
              p95_ms: Math.round(data.metrics.dashboard_load_latency_ms.values["p(95)"] || 0),
              p99_ms: Math.round(data.metrics.dashboard_load_latency_ms.values["p(99)"] || 0),
            }
          : null,
        field_stats: data.metrics.field_stats_latency_ms
          ? {
              p50_ms: Math.round(data.metrics.field_stats_latency_ms.values.med || 0),
              p95_ms: Math.round(data.metrics.field_stats_latency_ms.values["p(95)"] || 0),
              p99_ms: Math.round(data.metrics.field_stats_latency_ms.values["p(99)"] || 0),
            }
          : null,
      },
      null,
      2
    ),
    stdout: summary,
  };
}
