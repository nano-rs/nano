// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildObservationQueries,
  buildObservationQuery,
  DOMAIN_PATHS,
  HASH_PATHS,
  mergeDiscoveryResults,
  mergeObservations,
  OBSERVATION_BATCH_SIZE,
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

// NAN-4931: the OCSF profile reads the OCSF hash arrays / hostnames and keys
// hosts on device.hostname, not the UDM names (which match nothing there).
test('observationPathsFor picks the OCSF paths and host identity under OCSF', () => {
  const ocsf = observationPathsFor(true);
  assert.deepEqual([...ocsf.hashPaths], ['file.hashes.value', 'process.file.hashes.value', 'actor.process.file.hashes.value']);
  assert.ok(ocsf.domainPaths.includes('dst_endpoint.hostname'));
  assert.match(ocsf.hostEval, /device\.hostname/);
  const [q] = buildObservationQueries(['abc'], ocsf.hashPaths.slice(0, 1), ocsf.hostEval);
  assert.equal(
    q.npl,
    'file.hashes.value="abc" | eval __h=if(device.hostname!="", device.hostname, if(src_endpoint.hostname!="", src_endpoint.hostname, "unknown")) | stats dc(__h) as hosts, count as events, min(timestamp) as first_in_window by file.hashes.value',
  );
  const udm = observationPathsFor(false);
  assert.deepEqual([...udm.hashPaths], ['file_hash', 'process_hash']);
  assert.match(udm.hostEval, /src_host/);
});
