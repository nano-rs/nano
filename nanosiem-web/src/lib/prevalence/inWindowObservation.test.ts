// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import test from 'node:test';

import {
  buildObservationQueries,
  buildObservationQuery,
  DOMAIN_PATHS,
  HASH_PATHS,
  mergeDiscoveryResults,
  mergeObservations,
  OBSERVATION_BATCH_SIZE,
  OCSF_HOST_IDENTITY_EVAL,
  applyInWindowObservation,
  baselineFromScatterPoint,
  buildDiscoveryQuery,
  observationPathsFor,
} from './inWindowObservation.ts';

const HASH_A = '9728a804f1c4b7a1f3c2d5e6b7a8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f70';
const HASH_B = 'd4a566ae1ebc4f198f6bfee9def3ba543ffd727678886f7ed0f69d8728864b7f';

// NAN-2361: `field=*` was wrong in BOTH directions on the lake path -- measured
// on a pinned window it admitted 395/400 rows carrying no hash at all, and
// found 13 hosts for an artifact an equality filter proved was on 27. If this
// regresses to a wildcard the chart's counts silently become fiction.
test('observation query uses equality ORs, never an existence filter', () => {
  const { npl } = buildObservationQuery('file_hash', [HASH_A, HASH_B]);
  assert.ok(!npl.includes('=*'), 'must not emit an existence filter');
  assert.ok(npl.includes(`file_hash="${HASH_A}"`));
  assert.ok(npl.includes(' OR '));
});

// The ClickHouse prevalence MVs (clickhouse/129) key a host as
// `if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))`.
// Layer 1 must count the same thing. NOT `coalesce`: UDM string columns are
// '' when absent, and coalesce('') collapses host-less rows into one host
// (measured on the G22 e2e stack: 2 host-less IPs counted as 1).
test('observation query mirrors the baseline builder host identity', () => {
  const { npl } = buildObservationQuery('file_hash', [HASH_A]);
  assert.ok(npl.includes('eval __h=if(src_host!="", src_host, if(src_ip!="", src_ip, "unknown"))'), npl);
  assert.ok(!npl.includes('coalesce'));
  assert.ok(npl.includes('stats dc(__h) as hosts'));
  assert.ok(npl.includes('min(timestamp) as first_in_window'));
});

// The paths are the ones the baseline aggregates read (UDM names; under the
// OCSF schema profile they resolve to OCSF paths as nPL aliases).
test('observation paths mirror the baseline aggregates', () => {
  assert.deepEqual([...HASH_PATHS], ['file_hash', 'process_hash']);
  assert.deepEqual([...DOMAIN_PATHS], ['dest_host', 'query', 'url_domain']);
});

test('observation query groups by the queried path', () => {
  const { npl } = buildObservationQuery('process_hash', [HASH_A]);
  assert.ok(npl.endsWith('by process_hash'));
});

test('observation query strips quotes that would break out of the literal', () => {
  const { npl } = buildObservationQuery('dest_host', ['ev"il.com']);
  assert.ok(npl.includes('dest_host="evil.com"'));
  assert.ok(!npl.includes('ev"il'));
});

test('queries fan out across every candidate path', () => {
  const queries = buildObservationQueries([HASH_A], HASH_PATHS);
  assert.deepEqual(
    queries.map((q) => q.path),
    [...HASH_PATHS],
  );
});

test('queries chunk to the bulk limit', () => {
  const many = Array.from({ length: OBSERVATION_BATCH_SIZE * 2 + 1 }, (_, i) =>
    i.toString(16).padStart(64, '0'),
  );
  const queries = buildObservationQueries(many, ['file_hash']);
  assert.equal(queries.length, 3);
  assert.equal(queries[0].artifacts.length, OBSERVATION_BATCH_SIZE);
  assert.equal(queries[2].artifacts.length, 1);
});

test('no artifacts issues no queries', () => {
  assert.deepEqual(buildObservationQueries([], HASH_PATHS), []);
  assert.deepEqual(buildObservationQueries([], DOMAIN_PATHS), []);
});

// Hash paths group by the ARRAY, not the element. Today's data is >=99%
// single-element SHA-256, but a future [md5, sha256] row forms a composite key
// that equality matching would silently drop.
test('merge matches array group keys by containment', () => {
  const merged = mergeObservations(
    [HASH_A],
    [
      {
        path: 'file_hash',
        row: { 'file_hash': ['deadbeef', HASH_A], hosts: 4, events: 9 },
      },
    ],
  );
  assert.equal(merged.get(HASH_A)?.hosts, 4);
});

test('merge handles scalar group keys (domain paths)', () => {
  const merged = mergeObservations(
    ['evil.com'],
    [{ path: 'dest_host', row: { 'dest_host': 'evil.com', hosts: 2, events: 3 } }],
  );
  assert.equal(merged.get('evil.com')?.hosts, 2);
});

// The same host can appear under several paths; summing would overstate "how
// many machines have this", which is the dangerous direction for a rarity
// signal. Max understates instead, deliberately.
test('merge takes max hosts across paths, never the sum', () => {
  const merged = mergeObservations(
    [HASH_A],
    [
      { path: 'file_hash', row: { 'file_hash': [HASH_A], hosts: 6, events: 6 } },
      {
        path: 'process_hash',
        row: { 'process_hash': [HASH_A], hosts: 2, events: 4 },
      },
    ],
  );
  assert.equal(merged.get(HASH_A)?.hosts, 6);
  assert.equal(merged.get(HASH_A)?.events, 10);
});

// Regression: the seconds-vs-milliseconds threshold must be 1e11, not 1e12 --
// a timestamp landing exactly on 1e12 was being read as seconds and multiplied
// into the year 33658, losing the earliest-occurrence comparison.
test('merge keeps the earliest in-window occurrence across paths', () => {
  const merged = mergeObservations(
    [HASH_A],
    [
      {
        path: 'file_hash',
        row: { 'file_hash': [HASH_A], hosts: 1, first_in_window: 2_000_000_000_000 },
      },
      {
        path: 'process_hash',
        row: {
          'process_hash': [HASH_A],
          hosts: 1,
          first_in_window: 1_000_000_000_000,
        },
      },
    ],
  );
  assert.equal(merged.get(HASH_A)?.firstInWindow, 1_000_000_000_000);
});

test('merge ignores group keys that were not requested', () => {
  const merged = mergeObservations(
    [HASH_A],
    [{ path: 'file_hash', row: { 'file_hash': [HASH_B], hosts: 9 } }],
  );
  assert.equal(merged.has(HASH_B), false);
  assert.equal(merged.size, 0);
});

// The broken `=*` filter produced a huge `[]` bucket (2000 rows). Defence in
// depth: an empty group key is never an artifact.
test('merge drops the empty group key rather than inventing an artifact', () => {
  const merged = mergeObservations(
    [HASH_A],
    [{ path: 'file_hash', row: { 'file_hash': [], hosts: 2000 } }],
  );
  assert.equal(merged.size, 0);
});

test('merge matches case-insensitively and returns the requested casing', () => {
  const upper = HASH_A.toUpperCase();
  const merged = mergeObservations(
    [upper],
    [{ path: 'file_hash', row: { 'file_hash': [HASH_A], hosts: 3 } }],
  );
  assert.equal(merged.get(upper)?.hosts, 3);
});

test('merge coerces string-typed aggregate values', () => {
  const merged = mergeObservations(
    [HASH_A],
    [
      {
        path: 'file_hash',
        row: { 'file_hash': [HASH_A], hosts: '7', events: '12' },
      },
    ],
  );
  assert.equal(merged.get(HASH_A)?.hosts, 7);
  assert.equal(merged.get(HASH_A)?.events, 12);
});

// NAN-2361 discovery: a failed path (admission-control 429 after retries) must
// surface as `failedPaths`, NOT read as "found nothing" — the truncation banner
// keys off totalCount, which a failed path reports as null, so without this the
// chart claimed a complete artifact list while silently missing a whole path.
test('discovery merge reports failed paths distinctly from empty ones', () => {
  const out = mergeDiscoveryResults([
    {
      path: 'file_hash',
      rows: [{ 'file_hash': [HASH_A], hosts: 2, events: 5, first_in_window: 1_700_000_000 }],
      totalCount: 1,
    },
    { path: 'process_hash', rows: [], totalCount: 0 }, // genuinely empty
    { path: 'actor.process_hash', rows: [], totalCount: null, failed: true },
  ]);
  assert.deepEqual(out.failedPaths, ['actor.process_hash']);
  assert.equal(out.truncated, false); // a failure is not truncation
  assert.equal(out.observations.get(HASH_A)?.hosts, 2);
});

test('discovery merge flags truncation when a path hit its limit', () => {
  const out = mergeDiscoveryResults([
    {
      path: 'query.hostname',
      rows: [{ 'query.hostname': 'a.example.com', hosts: 1, events: 1, first_in_window: 1_700_000_000 }],
      totalCount: 3,
    },
  ]);
  assert.equal(out.truncated, true);
  assert.equal(out.totalArtifacts, 3);
  assert.deepEqual(out.failedPaths, []);
});

// NAN-4931: the OCSF profile reads the OCSF hash arrays / hostnames.
// NAN-5662: and keys hosts exactly like the OCSF prevalence MVs.
test('observationPathsFor picks the OCSF paths and host identity under OCSF', () => {
  const ocsf = observationPathsFor(true);
  assert.deepEqual([...ocsf.hashPaths], ['file.hashes.value', 'process.file.hashes.value', 'actor.process.file.hashes.value']);
  assert.ok(ocsf.domainPaths.includes('dst_endpoint.hostname'));
  assert.equal(ocsf.hostEval, OCSF_HOST_IDENTITY_EVAL);
  const [q] = buildObservationQueries(['abc'], ocsf.hashPaths.slice(0, 1), ocsf.hostEval);
  assert.equal(
    q.npl,
    'file.hashes.value="abc" | eval __h=if(src_endpoint.hostname!="", src_endpoint.hostname, if(src_endpoint.ip!="", src_endpoint.ip, if(device.hostname!="", device.hostname, "unknown"))) | stats dc(__h) as hosts, count as events, min(timestamp) as first_in_window by file.hashes.value',
  );
  const udm = observationPathsFor(false);
  assert.deepEqual([...udm.hashPaths], ['file_hash', 'process_hash']);
  assert.match(udm.hostEval, /src_host/);
});

// ---------------------------------------------------------------------------
// NAN-5662: OCSF host identity pinned to the prevalence MVs.
// ---------------------------------------------------------------------------

const repoUrl = (rel: string) => new URL(`../../../../${rel}`, import.meta.url);
const repoFile = (rel: string) => readFileSync(repoUrl(rel), 'utf8');
// These pins read the ClickHouse schema next to the web app; a checkout that
// carries only nanosiem-web skips them rather than failing.
const HAS_OCSF_SCHEMA = existsSync(repoUrl('clickhouse/ocsf/init.sql'));
const schemaTest = HAS_OCSF_SCHEMA ? test : test.skip;

/** The identity every OCSF hash/domain MV aggregates, with whitespace collapsed. */
const MV_HOST_KEY =
  "uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown'))))";

const squash = (sql: string) => sql.replace(/\s+/g, ' ').replace(/\( /g, '(').replace(/ \)/g, ')');

/** Each `CREATE MATERIALIZED VIEW <name> ... ;` body in an OCSF SQL file. */
function ocsfPrevalenceMvBodies(sql: string): Map<string, string> {
  const out = new Map<string, string>();
  const re = /CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem\.(\w+)([\s\S]*?);\n/g;
  for (const m of sql.matchAll(re)) out.set(m[1], squash(m[2]));
  return out;
}

const OCSF_HASH_AND_DOMAIN_MVS = [
  'ocsf_hash_prevalence_summary_file_hash_mv',
  'ocsf_hash_prevalence_summary_process_hash_mv',
  'ocsf_hash_prevalence_summary_actor_process_hash_mv',
  'ocsf_domain_prevalence_summary_dest_host_mv',
  'ocsf_domain_prevalence_summary_query_mv',
  'ocsf_domain_prevalence_summary_url_mv',
  'ocsf_domain_prevalence_summary_http_url_mv',
  'hash_prevalence_source_ocsf_mv',
  'hash_prevalence_source_ocsf_actor_process_mv',
  'domain_prevalence_source_ocsf_mv',
  'domain_prevalence_source_ocsf_http_url_mv',
];

schemaTest('every OCSF hash/domain prevalence MV keys hosts on the one identity the eval mirrors', () => {
  const bodies = ocsfPrevalenceMvBodies(repoFile('clickhouse/ocsf/init.sql'));
  for (const name of OCSF_HASH_AND_DOMAIN_MVS) {
    const body = bodies.get(name);
    assert.ok(body, `${name} missing from clickhouse/ocsf/init.sql`);
    assert.ok(body.includes(MV_HOST_KEY), `${name} no longer uses the host key the eval mirrors:\n${body}`);
  }
  // The upgrade path: the LATEST migration statement that (re)defines each of
  // these MVs must carry the same key, so a later MODIFY QUERY that changes
  // the identity fails here until the eval is changed with it.
  const names = new Set(OCSF_HASH_AND_DOMAIN_MVS);
  const latest = new Map<string, { mig: string; stmt: string }>();
  for (const mig of readdirSync(repoUrl('clickhouse/ocsf/migrations')).filter((f) => f.endsWith('.sql')).sort()) {
    const sql = repoFile(`clickhouse/ocsf/migrations/${mig}`).replace(/^\s*--.*$/gm, '');
    for (const stmt of sql.split(/;\s*\n/)) {
      const target = stmt.match(/(?:ALTER TABLE|CREATE MATERIALIZED VIEW(?: IF NOT EXISTS)?)\s+nanosiem\.(\w+)/)?.[1];
      if (target && names.has(target) && /uniqState/.test(stmt)) latest.set(target, { mig, stmt });
    }
  }
  // 196 redefines 7 of them and 197 creates 4: the scan really ran.
  assert.ok(latest.size >= 11, `only ${latest.size} MVs found in clickhouse/ocsf/migrations`);
  for (const [target, { mig, stmt }] of latest) {
    assert.ok(squash(stmt).includes(MV_HOST_KEY), `${mig}: ${target} changes the host key the eval mirrors`);
  }
});

schemaTest('the OCSF eval is the MV key transliterated (src_host_unified == device.hostname in its branch)', () => {
  const alias = squash(repoFile('clickhouse/ocsf/init.sql')).match(/`src_host_unified` String ALIAS ([^,]+, [^,]+, [^)]+\))/);
  assert.ok(alias, 'src_host_unified ALIAS not found');
  // ALIAS = if(src_endpoint.hostname non-empty, src_endpoint.hostname, device.hostname):
  // reached only when src_endpoint.hostname is '', it IS device.hostname.
  assert.equal(alias[1], 'if(notEmpty(`src_endpoint.hostname`), `src_endpoint.hostname`, `device.hostname`)');
  const fromMv = MV_HOST_KEY
    .replace(/^uniqState\(/, '')
    .replace(/\)$/, '')
    .replace(/`/g, '')
    .replace(/ != ''/g, '!=""')
    .replace(/'unknown'/g, '"unknown"')
    .replace(/src_host_unified/g, 'device.hostname');
  assert.equal(OCSF_HOST_IDENTITY_EVAL, `eval __h=${fromMv}`);
});

/** Evaluate the `eval __h=if(a!="", a, if(b!="", b, ... "unknown"))` chain on a row. */
function evalHostIdentity(evalStr: string, row: Record<string, string>): string {
  const fields = [...evalStr.matchAll(/if\(([\w.]+)!=""/g)].map((m) => m[1]);
  const fallback = evalStr.match(/"(\w+)"\)+$/)?.[1];
  assert.ok(fields.length > 0 && fallback, evalStr);
  for (const f of fields) if ((row[f] ?? '') !== '') return row[f];
  return fallback;
}

test('proxy rows carrying only src_endpoint.ip count distinct client IPs, not one host', () => {
  // A proxy log: the client IP, the requested host, and the appliance as device.
  const rows = Array.from({ length: 1108 }, (_, i) => ({
    'src_endpoint.ip': `10.${(i >> 8) & 255}.${i & 255}.7`,
    'device.hostname': 'proxy-01',
    'dst_endpoint.hostname': 'github.com',
  }));
  const hosts = new Set(rows.map((r) => evalHostIdentity(OCSF_HOST_IDENTITY_EVAL, r)));
  assert.equal(hosts.size, 1108);
  // Endpoint rows (Sysmon) have no src_endpoint and key on device.hostname.
  assert.equal(evalHostIdentity(OCSF_HOST_IDENTITY_EVAL, { 'device.hostname': 'ws-1' }), 'ws-1');
  assert.equal(evalHostIdentity(OCSF_HOST_IDENTITY_EVAL, { 'src_endpoint.hostname': 'h', 'src_endpoint.ip': '1.2.3.4' }), 'h');
  assert.equal(evalHostIdentity(OCSF_HOST_IDENTITY_EVAL, {}), 'unknown');
});

test('discovery query takes the profile host identity', () => {
  const { npl } = buildDiscoveryQuery('dst_endpoint.hostname=*', 'dst_endpoint.hostname', OCSF_HOST_IDENTITY_EVAL);
  assert.ok(npl.startsWith(`dst_endpoint.hostname=* | ${OCSF_HOST_IDENTITY_EVAL} | stats`), npl);
});

// ---------------------------------------------------------------------------
// NAN-5662: a baseline miss is never "rare" on its own.
// ---------------------------------------------------------------------------

const MISS = { host_count: 0, is_rare: true, prevalence_score: 0, total_occurrences: 0, first_seen: new Date().toISOString() };

test('a 0-host baseline miss is not rare and carries no env first-seen', () => {
  const b = baselineFromScatterPoint(MISS);
  assert.deepEqual(b, { hostCount: 0, isRare: false, prevalenceScore: 0, totalOccurrences: 0, envFirstSeen: undefined });
  assert.equal(baselineFromScatterPoint({ ...MISS, host_count: null }), null);
  const hit = baselineFromScatterPoint({ ...MISS, host_count: 2, is_rare: true, first_seen: '2026-11-01T00:00:00Z' });
  assert.equal(hit?.isRare, true);
  assert.equal(hit?.envFirstSeen?.toISOString(), '2026-11-01T00:00:00.000Z');
});

test('applyInWindowObservation decides rarity of a miss from the observation only', () => {
  const miss = { hostCount: 0, isRare: true };
  // No observation (fallback failed / not run): unbaselined, NOT rare.
  assert.deepEqual(applyInWindowObservation(miss, undefined, 3), { hostCount: 0, isRare: false });
  assert.deepEqual(applyInWindowObservation(miss, { hosts: 0, events: 0, firstInWindow: null }, 3), { hostCount: 0, isRare: false });
  // Observed on 1108 hosts: common, not rare.
  assert.deepEqual(applyInWindowObservation(miss, { hosts: 1108, events: 5000, firstInWindow: 1 }, 3), { hostCount: 1108, isRare: false, inWindow: true });
  assert.deepEqual(applyInWindowObservation(miss, { hosts: 2, events: 2, firstInWindow: 1 }, 3), { hostCount: 2, isRare: true, inWindow: true });
  // A real baseline count is never overwritten.
  const counted = { hostCount: 5, isRare: false };
  assert.equal(applyInWindowObservation(counted, { hosts: 1, events: 1, firstInWindow: 1 }, 3), counted);
});
