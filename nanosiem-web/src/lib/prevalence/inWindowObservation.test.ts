// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildObservationQueries,
  buildObservationQuery,
  DOMAIN_PATHS,
  harvestIngestStamps,
  HASH_PATHS,
  mergeDiscoveryResults,
  mergeObservations,
  OBSERVATION_BATCH_SIZE,
} from './inWindowObservation.ts';

/** Shaped from a real lake event (verified live 2026-08-21). */
function stampedRow(value: string, isNew: boolean, ts: number) {
  return {
    time: ts,
    enrichments: [
      {
        name: 'prevalence',
        provider: 'nano',
        type: 'reputation',
        short_desc: isNew ? 'new artifact' : 'observed',
        value,
        data: {
          artifact_type: 'hash',
          as_of: 'ingest',
          host_count: 1,
          host_count_saturated: false,
          is_new: isNew,
          is_rare: true,
        },
      },
    ],
  } as Record<string, unknown>;
}

const tsOf = (row: Record<string, unknown>) =>
  typeof row.time === 'number' ? row.time : null;

const HASH_A = '9728a804f1c4b7a1f3c2d5e6b7a8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f70';
const HASH_B = 'd4a566ae1ebc4f198f6bfee9def3ba543ffd727678886f7ed0f69d8728864b7f';

// NAN-2361: `field=*` is wrong in BOTH directions on the lake path -- measured
// on a pinned window it admitted 395/400 rows carrying no hash at all, and
// found 13 hosts for an artifact an equality filter proved was on 27. If this
// regresses to a wildcard the chart's counts silently become fiction.
test('observation query uses equality ORs, never an existence filter', () => {
  const { npl } = buildObservationQuery('file.hashes.value', [HASH_A, HASH_B]);
  assert.ok(!npl.includes('=*'), 'must not emit an existence filter');
  assert.ok(npl.includes(`file.hashes.value="${HASH_A}"`));
  assert.ok(npl.includes(' OR '));
});

// A plain dc(device.hostname) returns 0 for OCSF classes carrying no `device`
// object (verified against http_request rows). The baseline builder coalesces,
// so layer 1 must too, or the two layers count different things.
test('observation query mirrors the baseline builder host identity', () => {
  const { npl } = buildObservationQuery('file.hashes.value', [HASH_A]);
  assert.ok(npl.includes('coalesce(device.hostname, src_endpoint.hostname, "unknown")'));
  assert.ok(npl.includes('stats dc(__h) as hosts'));
});

test('observation query groups by the queried path', () => {
  const { npl } = buildObservationQuery('process.file.hashes.value', [HASH_A]);
  assert.ok(npl.endsWith('by process.file.hashes.value'));
});

test('observation query strips quotes that would break out of the literal', () => {
  const { npl } = buildObservationQuery('url.hostname', ['ev"il.com']);
  assert.ok(npl.includes('url.hostname="evil.com"'));
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
  const queries = buildObservationQueries(many, ['file.hashes.value']);
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
        path: 'file.hashes.value',
        row: { 'file.hashes.value': ['deadbeef', HASH_A], hosts: 4, events: 9 },
      },
    ],
  );
  assert.equal(merged.get(HASH_A)?.hosts, 4);
});

test('merge handles scalar group keys (domain paths)', () => {
  const merged = mergeObservations(
    ['evil.com'],
    [{ path: 'url.hostname', row: { 'url.hostname': 'evil.com', hosts: 2, events: 3 } }],
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
      { path: 'file.hashes.value', row: { 'file.hashes.value': [HASH_A], hosts: 6, events: 6 } },
      {
        path: 'process.file.hashes.value',
        row: { 'process.file.hashes.value': [HASH_A], hosts: 2, events: 4 },
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
        path: 'file.hashes.value',
        row: { 'file.hashes.value': [HASH_A], hosts: 1, first_in_window: 2_000_000_000_000 },
      },
      {
        path: 'process.file.hashes.value',
        row: {
          'process.file.hashes.value': [HASH_A],
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
    [{ path: 'file.hashes.value', row: { 'file.hashes.value': [HASH_B], hosts: 9 } }],
  );
  assert.equal(merged.has(HASH_B), false);
  assert.equal(merged.size, 0);
});

// The broken `=*` filter produced a huge `[]` bucket (2000 rows). Defence in
// depth: an empty group key is never an artifact.
test('merge drops the empty group key rather than inventing an artifact', () => {
  const merged = mergeObservations(
    [HASH_A],
    [{ path: 'file.hashes.value', row: { 'file.hashes.value': [], hosts: 2000 } }],
  );
  assert.equal(merged.size, 0);
});

test('merge matches case-insensitively and returns the requested casing', () => {
  const upper = HASH_A.toUpperCase();
  const merged = mergeObservations(
    [upper],
    [{ path: 'file.hashes.value', row: { 'file.hashes.value': [HASH_A], hosts: 3 } }],
  );
  assert.equal(merged.get(upper)?.hosts, 3);
});

test('merge coerces string-typed aggregate values', () => {
  const merged = mergeObservations(
    [HASH_A],
    [
      {
        path: 'file.hashes.value',
        row: { 'file.hashes.value': [HASH_A], hosts: '7', events: '12' },
      },
    ],
  );
  assert.equal(merged.get(HASH_A)?.hosts, 7);
  assert.equal(merged.get(HASH_A)?.events, 12);
});

// NAN-2361: `is_new` is evaluated against the SAME lagging snapshot, so during
// the 30-90 minute catch-up every occurrence of a fresh artifact is stamped
// new. Deduping per artifact (and pinning to the earliest occurrence) is what
// stops a single new artifact painting a novelty ring on every dot it owns.
test('stamp harvest dedupes newness per artifact and keeps the earliest', () => {
  const stamps = harvestIngestStamps(
    [
      stampedRow(HASH_A, true, 3_000),
      stampedRow(HASH_A, true, 1_000),
      stampedRow(HASH_A, true, 2_000),
    ],
    tsOf,
  );
  assert.equal(stamps.size, 1);
  assert.equal(stamps.get(HASH_A)?.isNew, true);
  assert.equal(stamps.get(HASH_A)?.earliestMs, 1_000);
});

test('stamp harvest treats any new occurrence as new', () => {
  const stamps = harvestIngestStamps(
    [stampedRow(HASH_A, false, 1_000), stampedRow(HASH_A, true, 2_000)],
    tsOf,
  );
  assert.equal(stamps.get(HASH_A)?.isNew, true);
});

test('stamp harvest ignores non-prevalence enrichments', () => {
  const row = {
    time: 1_000,
    enrichments: [{ name: 'geoip', value: HASH_A, data: { is_new: true } }],
  } as Record<string, unknown>;
  assert.equal(harvestIngestStamps([row], tsOf).size, 0);
});

// Rows with no `enrichments` are ClickHouse/UDM tenants and the fail-open
// cases. An empty map is the gate: callers skip the whole layer rather than
// branching on backend identity.
test('stamp harvest returns empty for rows without enrichments', () => {
  const rows = [{ time: 1_000, message: 'plain udm row' }] as Array<Record<string, unknown>>;
  assert.equal(harvestIngestStamps(rows, tsOf).size, 0);
});

test('stamp harvest parses a JSON-encoded enrichments column', () => {
  const row = {
    time: 5_000,
    enrichments: JSON.stringify([
      { name: 'prevalence', value: HASH_B, data: { is_new: true, as_of: 'ingest' } },
    ]),
  } as Record<string, unknown>;
  assert.equal(harvestIngestStamps([row], tsOf).get(HASH_B)?.isNew, true);
});

test('stamp harvest survives malformed enrichments without throwing', () => {
  const rows = [
    { time: 1, enrichments: 'not json at all' },
    { time: 2, enrichments: [null, 'string', { name: 'prevalence' }] },
    { time: 3, enrichments: [{ name: 'prevalence', value: '', data: {} }] },
  ] as Array<Record<string, unknown>>;
  assert.equal(harvestIngestStamps(rows, tsOf).size, 0);
});

// NAN-2361 discovery: a failed path (admission-control 429 after retries) must
// surface as `failedPaths`, NOT read as "found nothing" — the truncation banner
// keys off totalCount, which a failed path reports as null, so without this the
// chart claimed a complete artifact list while silently missing a whole path.
test('discovery merge reports failed paths distinctly from empty ones', () => {
  const out = mergeDiscoveryResults([
    {
      path: 'file.hashes.value',
      rows: [{ 'file.hashes.value': [HASH_A], hosts: 2, events: 5, first_in_window: 1_700_000_000 }],
      totalCount: 1,
    },
    { path: 'process.file.hashes.value', rows: [], totalCount: 0 }, // genuinely empty
    { path: 'actor.process.file.hashes.value', rows: [], totalCount: null, failed: true },
  ]);
  assert.deepEqual(out.failedPaths, ['actor.process.file.hashes.value']);
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
