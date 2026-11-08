/**
 * NanoSIEM Ingestion Benchmark (k6)
 *
 * Lightweight alternative to log-blaster for quick ingestion throughput tests.
 * For sustained high-EPS stress tests, use log-blaster's blast mode instead.
 *
 * Usage:
 *   k6 run --vus 10 --duration 60s benchmarks/k6/ingestion.js
 *
 * Environment variables:
 *   VECTOR_URL        - Vector HTTP endpoint (default: http://localhost:8080)
 *   VECTOR_AUTH_TOKEN  - Bearer token for Vector auth (optional)
 *   BATCH_SIZE         - Events per NDJSON batch (default: 100)
 */

import http from "k6/http";
import { check } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";

// Custom metrics
const eventsIngested = new Counter("events_ingested");
const ingestErrors = new Rate("ingest_error_rate");
const batchLatency = new Trend("batch_latency_ms", true);

const VECTOR_URL = __ENV.VECTOR_URL || "http://localhost:8080";
const AUTH_TOKEN = __ENV.VECTOR_AUTH_TOKEN || "";
const BATCH_SIZE = parseInt(__ENV.BATCH_SIZE || "100", 10);

// Configurable stages - ramp up to find saturation point
export const options = {
  scenarios: {
    ramp_eps: {
      executor: "ramping-vus",
      startVUs: 1,
      stages: [
        { duration: "15s", target: 5 },
        { duration: "30s", target: 10 },
        { duration: "30s", target: 20 },
        { duration: "30s", target: 40 },
        { duration: "15s", target: 0 },
      ],
    },
  },
  thresholds: {
    batch_latency_ms: ["p(95)<2000"],
    ingest_error_rate: ["rate<0.01"],
  },
};

// --- Log generators ---

const SOURCE_TYPES = [
  "apache_access",
  "defender_edr",
  "syslog",
  "aws_cloudtrail",
  "okta",
];

const APACHE_METHODS = ["GET", "POST", "PUT", "DELETE"];
const APACHE_PATHS = [
  "/api/users",
  "/api/search",
  "/api/alerts",
  "/login",
  "/dashboard",
  "/api/rules",
  "/health",
  "/api/settings",
];
const APACHE_STATUSES = [200, 200, 200, 200, 201, 301, 400, 401, 403, 404, 500];
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
  "curl/7.88.1",
  "python-requests/2.31.0",
];

const HOSTNAMES = Array.from({ length: 50 }, (_, i) => `WKS-${String(i).padStart(4, "0")}`);
const IPS = Array.from({ length: 50 }, (_, i) => `10.1.${Math.floor(i / 255)}.${(i % 255) + 1}`);
const USERS = ["jsmith", "agarcia", "bwilson", "clee", "dchen", "emiller", "admin", "svc-backup"];
const PROCESSES = [
  "chrome.exe", "explorer.exe", "powershell.exe", "cmd.exe",
  "svchost.exe", "notepad.exe", "outlook.exe", "teams.exe",
];
const DEFENDER_ACTIONS = [
  "ProcessCreated", "ConnectionSuccess", "FileCreated", "LogonSuccess",
];

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateApacheLog(ts) {
  const ip = randomItem(IPS);
  const user = Math.random() < 0.3 ? randomItem(USERS) : "-";
  const method = randomItem(APACHE_METHODS);
  const path = randomItem(APACHE_PATHS);
  const status = randomItem(APACHE_STATUSES);
  const bytes = randomInt(100, 50000);
  const ua = randomItem(USER_AGENTS);

  return {
    message: `${ip} - ${user} [${ts}] "${method} ${path} HTTP/1.1" ${status} ${bytes} "-" "${ua}"`,
    source_type: "apache_access",
    timestamp: new Date().toISOString(),
  };
}

function generateDefenderLog(ts) {
  const action = randomItem(DEFENDER_ACTIONS);
  const host = randomItem(HOSTNAMES);
  const user = randomItem(USERS);
  const process = randomItem(PROCESSES);

  return {
    message: JSON.stringify({
      ActionType: action,
      DeviceName: host,
      AccountName: user,
      ProcessCommandLine: `C:\\Windows\\System32\\${process}`,
      ProcessId: randomInt(1000, 65535),
      Timestamp: new Date().toISOString(),
    }),
    source_type: "defender_edr",
    timestamp: new Date().toISOString(),
  };
}

function generateSyslog(ts) {
  const facilities = ["kern", "auth", "daemon", "syslog"];
  const severities = ["info", "warning", "error", "notice"];
  const messages = [
    "Connection established from ${ip}",
    "Session opened for user ${user}",
    "Failed password for ${user} from ${ip}",
    "Accepted publickey for ${user} from ${ip}",
    "Service started successfully",
    "Disk usage at 85%",
  ];

  const msg = randomItem(messages)
    .replace("${ip}", randomItem(IPS))
    .replace("${user}", randomItem(USERS));

  return {
    message: `<${randomInt(0, 191)}>${ts} ${randomItem(HOSTNAMES)} ${randomItem(facilities)}: ${msg}`,
    source_type: "syslog",
    timestamp: new Date().toISOString(),
  };
}

function generateEvent() {
  const ts = new Date().toISOString();
  const r = Math.random();
  if (r < 0.40) return generateApacheLog(ts);
  if (r < 0.70) return generateDefenderLog(ts);
  return generateSyslog(ts);
}

// --- Main test function ---

export default function () {
  const events = [];
  for (let i = 0; i < BATCH_SIZE; i++) {
    events.push(JSON.stringify(generateEvent()));
  }
  const body = events.join("\n");

  const headers = {
    "Content-Type": "application/x-ndjson",
  };
  if (AUTH_TOKEN) {
    headers["Authorization"] = `Bearer ${AUTH_TOKEN}`;
  }

  const res = http.post(VECTOR_URL, body, { headers, tags: { name: "ingest_batch" } });

  const ok = check(res, {
    "status 200": (r) => r.status === 200,
    "latency < 2s": (r) => r.timings.duration < 2000,
  });

  eventsIngested.add(BATCH_SIZE);
  ingestErrors.add(!ok);
  batchLatency.add(res.timings.duration);
}

export function handleSummary(data) {
  const duration = data.state.testRunDurationMs / 1000;
  const totalEvents = data.metrics.events_ingested
    ? data.metrics.events_ingested.values.count
    : 0;
  const avgEps = totalEvents / duration;
  const p95 = data.metrics.batch_latency_ms
    ? data.metrics.batch_latency_ms.values["p(95)"]
    : 0;
  const p99 = data.metrics.batch_latency_ms
    ? data.metrics.batch_latency_ms.values["p(99)"]
    : 0;
  const errRate = data.metrics.ingest_error_rate
    ? data.metrics.ingest_error_rate.values.rate
    : 0;

  const summary = `
╔══════════════════════════════════════════════════════╗
║           INGESTION BENCHMARK RESULTS                ║
╠══════════════════════════════════════════════════════╣
║  Duration:        ${duration.toFixed(1).padStart(10)}s                    ║
║  Total Events:    ${String(totalEvents).padStart(10)}                     ║
║  Avg EPS:         ${avgEps.toFixed(0).padStart(10)}                     ║
║  Batch p95:       ${p95.toFixed(1).padStart(10)}ms                   ║
║  Batch p99:       ${p99.toFixed(1).padStart(10)}ms                   ║
║  Error Rate:      ${(errRate * 100).toFixed(2).padStart(10)}%                    ║
╚══════════════════════════════════════════════════════╝
`;
  console.log(summary);

  return {
    "benchmarks/results/ingestion.json": JSON.stringify(
      {
        timestamp: new Date().toISOString(),
        test: "ingestion",
        duration_s: duration,
        total_events: totalEvents,
        avg_eps: Math.round(avgEps),
        batch_latency_p95_ms: Math.round(p95),
        batch_latency_p99_ms: Math.round(p99),
        error_rate: errRate,
        config: {
          vector_url: VECTOR_URL,
          batch_size: BATCH_SIZE,
        },
      },
      null,
      2
    ),
    stdout: summary,
  };
}
