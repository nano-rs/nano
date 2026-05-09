/**
 * NanoSIEM Search Benchmark (k6)
 *
 * Measures nPL query latency across different query types and time ranges.
 * Requires data already ingested (run ingestion benchmark or log-blaster first).
 *
 * Usage:
 *   k6 run benchmarks/k6/search.js
 *
 * Environment variables:
 *   SEARCH_URL   - Search service URL (default: http://localhost:3002)
 *   API_KEY      - API key for auth (required)
 *   JWT_TOKEN    - JWT bearer token (alternative to API_KEY)
 *   TIME_RANGE   - Lookback period: 1h, 24h, 7d, 30d (default: 24h)
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

// Per-query-type metrics — round-trip (client-side)
const queryLatency = new Trend("query_latency_ms", true);
const keywordLatency = new Trend("keyword_latency_ms", true);
const simpleSearchLatency = new Trend("simple_search_latency_ms", true);
const statsLatency = new Trend("stats_query_latency_ms", true);
const timechartLatency = new Trend("timechart_latency_ms", true);
const regexLatency = new Trend("regex_query_latency_ms", true);
const filterLatency = new Trend("filter_chain_latency_ms", true);
const prevalenceLatency = new Trend("prevalence_latency_ms", true);
const evalLatency = new Trend("eval_latency_ms", true);
const advancedLatency = new Trend("advanced_latency_ms", true);

// Server-side execution time (from response body execution_time_ms)
const serverLatency = new Trend("server_latency_ms", true);
const keywordServerLatency = new Trend("keyword_server_latency_ms", true);
const simpleServerLatency = new Trend("simple_server_latency_ms", true);
const statsServerLatency = new Trend("stats_server_latency_ms", true);
const timechartServerLatency = new Trend("timechart_server_latency_ms", true);
const regexServerLatency = new Trend("regex_server_latency_ms", true);
const filterServerLatency = new Trend("filter_chain_server_latency_ms", true);
const prevalenceServerLatency = new Trend("prevalence_server_latency_ms", true);
const evalServerLatency = new Trend("eval_server_latency_ms", true);
const advancedServerLatency = new Trend("advanced_server_latency_ms", true);

// Network overhead = round-trip - server execution
const networkOverhead = new Trend("network_overhead_ms", true);

const queryErrors = new Rate("query_error_rate");
const queriesExecuted = new Counter("queries_executed");

const SEARCH_URL = __ENV.SEARCH_URL || "http://localhost:3002";
const API_KEY = __ENV.API_KEY || "";
const JWT_TOKEN = __ENV.JWT_TOKEN || "";
const TIME_RANGE_PARAM = __ENV.TIME_RANGE || "24h";

export const options = {
  scenarios: {
    // Warm-up then steady state
    search_load: {
      executor: "constant-vus",
      vus: 3,
      duration: "5m",
    },
  },
  thresholds: {
    query_latency_ms: ["p(95)<30000"],
    query_error_rate: ["rate<0.20"],
  },
};

// --- Time range helpers ---

function parseTimeRange(spec) {
  const now = new Date();
  const match = spec.match(/^(\d+)(h|d)$/);
  if (!match) return { start: new Date(now - 86400000), end: now };

  const val = parseInt(match[1], 10);
  const unit = match[2];
  const ms = unit === "h" ? val * 3600000 : val * 86400000;
  return {
    start: new Date(now.getTime() - ms),
    end: now,
  };
}

const TIME_RANGE = parseTimeRange(TIME_RANGE_PARAM);

function timeRange() {
  return {
    start: TIME_RANGE.start.toISOString(),
    end: TIME_RANGE.end.toISOString(),
  };
}

// --- Query definitions ---
// Each query represents a realistic analyst workflow pattern

const QUERIES = [
  // Keyword searches (message_search via hasToken / bloom filters)
  {
    name: "kw_error",
    type: "keyword",
    query: "error",
    limit: 100,
  },
  {
    name: "kw_denied",
    type: "keyword",
    query: "denied",
    limit: 100,
  },
  {
    name: "kw_failed",
    type: "keyword",
    query: "failed",
    limit: 100,
  },
  {
    name: "kw_timeout",
    type: "keyword",
    query: "timeout",
    limit: 100,
  },
  {
    name: "kw_powershell",
    type: "keyword",
    query: "powershell",
    limit: 100,
  },
  {
    name: "kw_rundll32",
    type: "keyword",
    query: "rundll32",
    limit: 100,
  },
  {
    name: "kw_cmd_exe",
    type: "keyword",
    query: "cmd.exe",
    limit: 100,
  },
  {
    name: "kw_admin",
    type: "keyword",
    query: "administrator",
    limit: 100,
  },
  {
    name: "kw_multi",
    type: "keyword",
    query: "error OR denied OR timeout",
    limit: 100,
  },
  {
    name: "kw_404",
    type: "keyword",
    query: "404",
    limit: 100,
  },

  // Field filter searches
  {
    name: "source_type_filter",
    type: "simple",
    query: 'source_type=apache_access',
    limit: 100,
  },
  {
    name: "ip_search",
    type: "simple",
    query: 'src_ip="10.1.0.1"',
    limit: 100,
  },
  {
    name: "user_search",
    type: "simple",
    query: 'user="admin"',
    limit: 100,
  },
  {
    name: "multi_field",
    type: "simple",
    query: 'source_type=defender_edr action=process_create',
    limit: 100,
  },

  // Stats / aggregation queries
  {
    name: "stats_count_by_source",
    type: "stats",
    query: "| stats count by source_type",
    limit: 1000,
  },
  {
    name: "stats_count_by_ip",
    type: "stats",
    query: "| stats count by src_ip | sort -count | head 20",
    limit: 1000,
  },
  {
    name: "stats_unique_users",
    type: "stats",
    query: "| stats dc(user) as unique_users by source_type",
    limit: 1000,
  },
  {
    name: "stats_bytes_by_host",
    type: "stats",
    query: "source_type=apache_access | stats sum(bytes_out) as total_bytes by src_ip | sort -total_bytes | head 10",
    limit: 1000,
  },

  // Timechart queries (histogram generation)
  {
    name: "timechart_all",
    type: "timechart",
    query: "| timechart span=1h count",
    limit: 1000,
  },
  {
    name: "timechart_by_source",
    type: "timechart",
    query: "| timechart span=1h count by source_type",
    limit: 1000,
  },
  {
    name: "timechart_errors",
    type: "timechart",
    query: 'http_status_code>=400 | timechart span=15m count',
    limit: 1000,
  },

  // Regex queries
  {
    name: "regex_powershell",
    type: "regex",
    query: 'command_line=/powershell.*-enc.*/i',
    limit: 100,
  },
  {
    name: "regex_ip_pattern",
    type: "regex",
    query: 'message=/\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/',
    limit: 100,
  },

  // Complex filter chains (realistic SOC hunting)
  {
    name: "hunt_lateral_movement",
    type: "filter_chain",
    query: 'source_type=defender_edr action=login | stats count by src_ip, dest_ip | where count > 5 | sort -count',
    limit: 1000,
  },
  {
    name: "hunt_high_volume_src",
    type: "filter_chain",
    query: '| stats count by src_ip | where count > 100 | sort -count | head 20',
    limit: 1000,
  },
  {
    name: "hunt_process_chain",
    type: "filter_chain",
    query: 'source_type=defender_edr action=process_create | stats count by process_name | sort -count | head 20',
    limit: 1000,
  },

  // Prevalence queries
  {
    name: "prevalence_rare_files",
    type: "prevalence",
    query: '| where prevalence_min < 20',
    limit: 100,
  },
  {
    name: "prevalence_rare_dest_ip",
    type: "prevalence",
    query: '| where prevalence_dest_ip < 10',
    limit: 100,
  },
  {
    name: "prevalence_new_hashes",
    type: "prevalence",
    query: 'source_type=defender_edr | where prevalence_file_hash < 5',
    limit: 100,
  },
  // Eval queries (compute functions)
  {
    name: "eval_is_private_ip",
    type: "eval",
    query: 'src_ip != "" | eval is_internal = is_private_ip(src_ip) | stats count by is_internal',
    limit: 1000,
  },
  {
    name: "eval_extract_domain",
    type: "eval",
    query: 'source_type=apache_access | eval domain = extract_domain(http_referrer) | stats count by domain | sort -count | head 20',
    limit: 1000,
  },
  {
    name: "eval_math",
    type: "eval",
    query: 'source_type=apache_access | eval total_bytes = bytes_in + bytes_out | stats avg(total_bytes) as avg_b, percentile(total_bytes, 95) as p95_b by src_ip | sort -avg_b | head 20',
    limit: 1000,
  },
  {
    name: "eval_string_len",
    type: "eval",
    query: 'source_type=apache_access | eval path_len = len(uri_path) | stats avg(path_len) as avg_len by uri_path | sort -avg_len | head 20',
    limit: 1000,
  },
  {
    name: "eval_conditional",
    type: "eval",
    query: '| eval has_user = if(user != "", "yes", "no") | stats count by has_user',
    limit: 1000,
  },
  {
    name: "eval_long_commands",
    type: "eval",
    query: 'source_type=defender_edr | eval cmd_len = len(command_line) | where cmd_len > 200 | head 50',
    limit: 100,
  },

  // Advanced commands
  {
    name: "dedup_users",
    type: "advanced",
    query: 'source_type=defender_edr action=login | dedup user | table user, src_ip, src_host',
    limit: 1000,
  },
  {
    name: "top_processes",
    type: "advanced",
    query: 'source_type=defender_edr | top limit=20 process_name',
    limit: 1000,
  },
  {
    name: "rare_processes",
    type: "advanced",
    query: 'source_type=defender_edr | rare limit=20 process_name',
    limit: 1000,
  },
  {
    name: "eventstats_baseline",
    type: "advanced",
    query: 'source_type=apache_access | eventstats avg(bytes_out) as avg_bytes | where bytes_out > avg_bytes * 3 | head 50',
    limit: 100,
  },
];

// --- Auth headers ---

function authHeaders() {
  const headers = { "Content-Type": "application/json" };
  if (JWT_TOKEN) {
    headers["Authorization"] = `Bearer ${JWT_TOKEN}`;
  }
  if (API_KEY) {
    headers["X-API-Key"] = API_KEY;
  }
  return headers;
}

// --- Metric router ---

function recordLatency(type, roundTrip, serverTime) {
  queryLatency.add(roundTrip);
  if (serverTime != null) {
    serverLatency.add(serverTime);
    networkOverhead.add(roundTrip - serverTime);
  }

  switch (type) {
    case "keyword":
      keywordLatency.add(roundTrip);
      if (serverTime != null) keywordServerLatency.add(serverTime);
      break;
    case "simple":
      simpleSearchLatency.add(roundTrip);
      if (serverTime != null) simpleServerLatency.add(serverTime);
      break;
    case "stats":
      statsLatency.add(roundTrip);
      if (serverTime != null) statsServerLatency.add(serverTime);
      break;
    case "timechart":
      timechartLatency.add(roundTrip);
      if (serverTime != null) timechartServerLatency.add(serverTime);
      break;
    case "regex":
      regexLatency.add(roundTrip);
      if (serverTime != null) regexServerLatency.add(serverTime);
      break;
    case "filter_chain":
      filterLatency.add(roundTrip);
      if (serverTime != null) filterServerLatency.add(serverTime);
      break;
    case "prevalence":
      prevalenceLatency.add(roundTrip);
      if (serverTime != null) prevalenceServerLatency.add(serverTime);
      break;
    case "eval":
      evalLatency.add(roundTrip);
      if (serverTime != null) evalServerLatency.add(serverTime);
      break;
    case "advanced":
      advancedLatency.add(roundTrip);
      if (serverTime != null) advancedServerLatency.add(serverTime);
      break;
  }
}

function extractServerTime(res) {
  if (res.status !== 200 || !res.body) return null;
  try {
    const body = JSON.parse(res.body);
    return body.execution_time_ms != null ? body.execution_time_ms : null;
  } catch {
    return null;
  }
}

// --- Main test function ---

export default function () {
  const headers = authHeaders();

  for (const q of QUERIES) {
    group(q.name, function () {
      const payload = JSON.stringify({
        query: q.query,
        time_range: timeRange(),
        limit: q.limit,
        skip_field_stats: true,
        table_view: true,
        request_id: `bench-${q.name}-${Date.now()}`,
      });

      const res = http.post(`${SEARCH_URL}/api/search`, payload, {
        headers,
        tags: { name: q.name, query_type: q.type },
      });

      const ok = check(
        res,
        {
          "status 200": (r) => r.status === 200,
          "valid response": (r) => {
            if (r.status !== 200) return false;
            if (!r.body) return false;
            try {
              const body = JSON.parse(r.body);
              return body.results !== undefined || body.error === undefined;
            } catch {
              // Large responses may not parse; status 200 is sufficient
              return true;
            }
          },
        },
        { name: q.name }
      );

      const serverTime = extractServerTime(res);

      queriesExecuted.add(1);
      queryErrors.add(!ok);
      recordLatency(q.type, res.timings.duration, serverTime);
    });

    // Small pause between queries to avoid overwhelming the search service
    sleep(0.2);
  }
}

export function handleSummary(data) {
  const duration = data.state.testRunDurationMs / 1000;
  const total = data.metrics.queries_executed
    ? data.metrics.queries_executed.values.count
    : 0;
  const errRate = data.metrics.query_error_rate
    ? data.metrics.query_error_rate.values.rate
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

  function dualLine(name, rtMetric, srvMetric) {
    const dash = "-".padStart(8);
    let rt = `${dash}   ${dash}   ${dash}`;
    let srv = `${dash}   ${dash}   ${dash}`;
    if (rtMetric) {
      const v = rtMetric.values;
      rt = `${pval(v, "med").padStart(8)}ms ${pval(v, "p(95)").padStart(8)}ms ${pval(v, "p(99)").padStart(8)}ms`;
    }
    if (srvMetric) {
      const v = srvMetric.values;
      srv = `${pval(v, "med").padStart(8)}ms ${pval(v, "p(95)").padStart(8)}ms ${pval(v, "p(99)").padStart(8)}ms`;
    }
    return `  ${name.padEnd(22)} ${rt}   ${srv}`;
  }

  const netOverhead = data.metrics.network_overhead_ms;
  const avgNet = netOverhead ? Math.round(netOverhead.values.med) : "?";

  const summary = `
╔═══════════════════════════════════════════════════════════════════════════════╗
║                      SEARCH BENCHMARK RESULTS                                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Duration:        ${duration.toFixed(1).padStart(10)}s                                             ║
║  Total Queries:   ${String(total).padStart(10)}                                              ║
║  Error Rate:      ${(errRate * 100).toFixed(2).padStart(10)}%                                             ║
║  Time Range:      ${TIME_RANGE_PARAM.padStart(10)}                                              ║
║  Network p50:     ${String(avgNet).padStart(10)}ms  (round-trip minus server execution)       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                         Round-Trip (client)         Server (ClickHouse)      ║
║  Query Type             p50       p95       p99     p50       p95       p99  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
${dualLine("All Queries", data.metrics.query_latency_ms, data.metrics.server_latency_ms)}
${dualLine("Keyword (bloom)", data.metrics.keyword_latency_ms, data.metrics.keyword_server_latency_ms)}
${dualLine("Field Filter", data.metrics.simple_search_latency_ms, data.metrics.simple_server_latency_ms)}
${dualLine("Stats/Aggregation", data.metrics.stats_query_latency_ms, data.metrics.stats_server_latency_ms)}
${dualLine("Timechart", data.metrics.timechart_latency_ms, data.metrics.timechart_server_latency_ms)}
${dualLine("Regex", data.metrics.regex_query_latency_ms, data.metrics.regex_server_latency_ms)}
${dualLine("Filter Chain (Hunt)", data.metrics.filter_chain_latency_ms, data.metrics.filter_chain_server_latency_ms)}
${dualLine("Prevalence", data.metrics.prevalence_latency_ms, data.metrics.prevalence_server_latency_ms)}
${dualLine("Eval Functions", data.metrics.eval_latency_ms, data.metrics.eval_server_latency_ms)}
${dualLine("Advanced Cmds", data.metrics.advanced_latency_ms, data.metrics.advanced_server_latency_ms)}
╚═══════════════════════════════════════════════════════════════════════════════╝
`;
  console.log(summary);

  function extractMetric(m) {
    if (!m) return null;
    return {
      p50_ms: Math.round(m.values.med || 0),
      p95_ms: Math.round(m.values["p(95)"] || 0),
      p99_ms: Math.round(m.values["p(99)"] || 0),
      avg_ms: Math.round(m.values.avg),
      min_ms: Math.round(m.values.min),
      max_ms: Math.round(m.values.max),
      count: m.values.count,
    };
  }

  // Build per-query-type results
  const queryTypes = {};
  const rtKeys = [
    "keyword_latency_ms",
    "simple_search_latency_ms",
    "stats_query_latency_ms",
    "timechart_latency_ms",
    "regex_query_latency_ms",
    "filter_chain_latency_ms",
    "prevalence_latency_ms",
    "eval_latency_ms",
    "advanced_latency_ms",
  ];
  const srvKeys = [
    "keyword_server_latency_ms",
    "simple_server_latency_ms",
    "stats_server_latency_ms",
    "timechart_server_latency_ms",
    "regex_server_latency_ms",
    "filter_chain_server_latency_ms",
    "prevalence_server_latency_ms",
    "eval_server_latency_ms",
    "advanced_server_latency_ms",
  ];
  for (let i = 0; i < rtKeys.length; i++) {
    const name = rtKeys[i].replace("_latency_ms", "");
    queryTypes[name] = {
      round_trip: extractMetric(data.metrics[rtKeys[i]]),
      server: extractMetric(data.metrics[srvKeys[i]]),
    };
  }

  return {
    "benchmarks/results/search.json": JSON.stringify(
      {
        timestamp: new Date().toISOString(),
        test: "search",
        duration_s: duration,
        total_queries: total,
        error_rate: errRate,
        time_range: TIME_RANGE_PARAM,
        overall: {
          round_trip: extractMetric(data.metrics.query_latency_ms),
          server: extractMetric(data.metrics.server_latency_ms),
          network_overhead: extractMetric(data.metrics.network_overhead_ms),
        },
        by_type: queryTypes,
        config: {
          search_url: SEARCH_URL,
          vus: data.state.vus,
        },
      },
      null,
      2
    ),
    stdout: summary,
  };
}
