#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-2361 live-scenario proof for the rarity chart's prevalence layers.
//
// This drives the REAL module the UI uses (buildObservationQueries /
// mergeObservations / harvestIngestStamps) against the REAL running stack, and
// asserts the property that was broken: an artifact the baseline has never
// heard of must still end up with a plottable host count and an explicit
// provenance, instead of silently becoming host_count 0.
//
// Usage:
//   NANO_API_KEY=... [NANO_SEARCH_URL=http://127.0.0.1:3002]
//   [NANO_PREVALENCE_URL=http://127.0.0.1:3000] [NANO_JWT=...]
//   node scripts/validate-in-window-prevalence.mjs [--minutes 45]
//
// The JWT is optional: without it the baseline lookup is skipped and the run
// proves layer 1 only. It is never derived from a password here -- pass one
// obtained out of band.

import {
  buildObservationQueries,
  DOMAIN_PATHS,
  harvestIngestStamps,
  HASH_PATHS,
  mergeObservations,
} from '../src/lib/prevalence/inWindowObservation.ts';

const SEARCH_URL = process.env.NANO_SEARCH_URL ?? 'http://127.0.0.1:3002';
const PREVALENCE_URL = process.env.NANO_PREVALENCE_URL ?? 'http://127.0.0.1:3000';
const API_KEY = process.env.NANO_API_KEY;
const JWT = process.env.NANO_JWT;
const WORKER_URL = process.env.NANO_LAKE_QUERY_URL ?? 'http://127.0.0.1:3015';
const WORKER_TOKEN = process.env.NANO_LAKE_QUERY_TOKEN;
const TENANT = process.env.NANO_LAKE_TENANT_ID ?? 'tenant-a';
const SNAPSHOT_ID = process.env.NANO_LAKE_PREVALENCE_SNAPSHOT_1H ?? `prevalence-${TENANT}-1h`;
const minutesArg = process.argv.indexOf('--minutes');
const MINUTES = minutesArg > -1 ? Number(process.argv[minutesArg + 1]) : 45;

if (!API_KEY) {
  console.error('NANO_API_KEY is required');
  process.exit(2);
}

const end = new Date();
const start = new Date(end.getTime() - MINUTES * 60_000);
const timeRange = { start: iso(start), end: iso(end) };

function iso(d) {
  return `${d.toISOString().slice(0, 19)}Z`;
}

async function search(query, limit) {
  const res = await fetch(`${SEARCH_URL}/api/search`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
    body: JSON.stringify({ query, time_range: timeRange, limit, skip_histogram: true }),
  });
  if (!res.ok) throw new Error(`search ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return (await res.json()).results ?? [];
}

/**
 * Baseline lookup.
 *
 * Prefers the lake worker's own endpoint with its runtime token file
 * (NANO_LAKE_QUERY_TOKEN), because that needs no user credential at all -- the
 * API route in front of it requires an interactive login, and a validation
 * script should never want a password. Falls back to the API route when a JWT
 * is supplied out of band.
 */
async function baselineLookup(hashes) {
  if (WORKER_TOKEN) {
    const res = await fetch(`${WORKER_URL}/v1/prevalence/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${WORKER_TOKEN}` },
      body: JSON.stringify({
        request_id: `validate-${Date.now()}`,
        tenant_id: TENANT,
        snapshot_id: SNAPSHOT_ID,
        window: '1h',
        // artifacts are RAW strings on this endpoint, not objects
        artifacts: hashes,
        deny_source_types: [],
      }),
    });
    if (!res.ok) {
      console.warn(`  ! worker lookup ${res.status} — continuing without baseline`);
      return null;
    }
    const body = await res.json();
    return { hash_points: (body.results ?? []).map((r) => ({ artifact: r.artifact ?? r.entity })) };
  }
  if (!JWT) return null;
  const res = await fetch(`${PREVALENCE_URL}/api/prevalence/scatter`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${JWT}` },
    body: JSON.stringify({ artifacts: { hashes, domains: [], ips: [] }, window: '24h' }),
  });
  if (!res.ok) {
    console.warn(`  ! baseline lookup ${res.status} — continuing without it`);
    return null;
  }
  return res.json();
}

const fail = [];
function check(label, cond, detail) {
  console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ` — ${detail}` : ''}`);
  if (!cond) fail.push(label);
}

console.log(`window ${timeRange.start} .. ${timeRange.end}`);

// 1. Load rows the way the chart does (full projection).
const rows = await search('*', 500);
console.log(`\nrows loaded: ${rows.length}`);

// 2. Harvest artifacts + ingest stamps from those rows.
const HASH_RE = /\b[0-9a-f]{64}\b/g;
const hashes = [...new Set(rows.flatMap((r) => JSON.stringify(r).match(HASH_RE) ?? []))].slice(0, 24);
const stamps = harvestIngestStamps(rows, (row) => {
  const raw = row.timestamp ?? row.time;
  if (raw == null) return null;
  const parsed = typeof raw === 'number' ? raw : Date.parse(String(raw));
  return Number.isFinite(parsed) ? parsed : null;
});
console.log(`hashes discovered: ${hashes.length}   ingest stamps: ${stamps.size}`);
check('ingest stamps present (lake-shaped rows)', stamps.size > 0);

// 3. Layer 1 — the exact queries the chart issues.
const queries = buildObservationQueries(hashes, HASH_PATHS);
console.log(`\nlayer 1: ${queries.length} queries across ${HASH_PATHS.length} paths`);
const t0 = Date.now();
const settled = await Promise.all(
  queries.map(async (q) => {
    try {
      const results = await search(q.npl, Math.max(250, q.artifacts.length * 2));
      return results.map((row) => ({ path: q.path, row }));
    } catch (error) {
      console.warn(`  ! ${q.path}: ${String(error).slice(0, 120)}`);
      return [];
    }
  }),
);
const elapsed = Date.now() - t0;
const observations = mergeObservations(hashes, settled.flat());
console.log(`layer 1 resolved ${observations.size}/${hashes.length} artifacts in ${elapsed}ms`);

check('layer 1 resolved at least one artifact', observations.size > 0);
check('layer 1 never exceeds requested artifacts', observations.size <= hashes.length);
check(
  'every observation has a positive host count',
  [...observations.values()].every((o) => o.hosts > 0),
  [...observations.values()].map((o) => o.hosts).slice(0, 6).join(','),
);
check('layer 1 completes under 5s', elapsed < 5000, `${elapsed}ms`);

// 4. Layer 2 — the baseline, and the gap layer 1 fills.
const baseline = await baselineLookup(hashes);
if (baseline) {
  const hit = new Set((baseline.hash_points ?? []).map((p) => p.artifact.toLowerCase()));
  const missed = hashes.filter((h) => !hit.has(h.toLowerCase()));
  const rescued = missed.filter((h) => observations.has(h));
  console.log(`\nlayer 2 baseline: ${hit.size}/${hashes.length} answered`);
  console.log(`baseline misses:  ${missed.length}   of which layer 1 rescues: ${rescued.length}`);
  check(
    'layer 1 rescues artifacts the baseline missed',
    missed.length === 0 || rescued.length > 0,
    `${rescued.length}/${missed.length}`,
  );
  // THE regression: before this change every one of these rendered as
  // host_count 0 / "not rare" / receded — indistinguishable from boring.
  const wouldHaveBeenZero = rescued.map((h) => observations.get(h).hosts);
  if (wouldHaveBeenZero.length) {
    console.log(
      `  artifacts that used to plot as 0 now plot at: ${wouldHaveBeenZero.slice(0, 8).join(', ')} hosts`,
    );
    check('rescued artifacts have real host counts', wouldHaveBeenZero.every((n) => n > 0));
  }
} else {
  console.log('\nlayer 2 baseline: skipped (no worker token / JWT)');
}

console.log(`\n${fail.length === 0 ? 'ALL CHECKS PASSED' : `FAILED: ${fail.join('; ')}`}`);
process.exit(fail.length === 0 ? 0 : 1);
