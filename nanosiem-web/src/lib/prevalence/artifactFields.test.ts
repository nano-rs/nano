// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  artifactCandidates,
  OCSF_DOMAIN_FIELDS,
  OCSF_HASH_FIELDS,
  readField,
  UDM_DOMAIN_FIELDS,
  UDM_HASH_FIELDS,
} from './artifactFields.ts';
import { DOMAIN_PATHS, HASH_PATHS, OCSF_DOMAIN_PATHS, OCSF_HASH_PATHS } from './inWindowObservation.ts';

const SHA = 'd4a566ae1ebc4f198f6bfee9def3ba543ffd727678886f7ed0f69d8728864b7f';

// Shape of a real conduit_proxy (OCSF HTTP Activity) row from /api/search:
// flat dotted keys, NO UDM columns. Before NAN-5270 this yielded zero artifacts.
const CONDUIT_ROW: Record<string, unknown> = {
  class_uid: 4002,
  'dst_endpoint.hostname': 'displaycatalog.mp.microsoft.com',
  'dst_endpoint.ip': '72.153.18.145',
  'src_endpoint.ip': '10.1.4.252',
  'http_request.url.hostname': 'displaycatalog.mp.microsoft.com',
  'http_request.url.url_string': 'https://displaycatalog.mp.microsoft.com/.well-known/security.txt',
  url_domain_unified: 'displaycatalog.mp.microsoft.com',
  url_unified: 'https://displaycatalog.mp.microsoft.com/.well-known/security.txt',
  message: '',
};

test('OCSF proxy row yields its hostname and URL candidates', () => {
  const c = artifactCandidates(CONDUIT_ROW);
  assert.ok(c.domains.includes('displaycatalog.mp.microsoft.com'));
  assert.ok(c.urls.includes('https://displaycatalog.mp.microsoft.com/.well-known/security.txt'));
  assert.deepEqual(c.hashes, []);
});

test('OCSF hashes: scalar sha256 and hashes.value arrays, flat or nested', () => {
  const flat = artifactCandidates({ 'process.file.hashes.sha256': SHA, 'file.hashes.value': ['a'.repeat(32), ''] });
  assert.ok(flat.hashes.includes(SHA));
  assert.ok(flat.hashes.includes('a'.repeat(32)));
  const nested = artifactCandidates({ file: { hashes: { sha256: SHA } }, query: { hostname: 'evil.example.com' } });
  assert.ok(nested.hashes.includes(SHA));
  assert.ok(nested.domains.includes('evil.example.com'));
});

test('UDM rows keep working (legacy events)', () => {
  const c = artifactCandidates({
    file_hash: SHA,
    metadata: { process_hash: 'b'.repeat(64) },
    dest_host: 'example.org',
    query: 'dns.example.net',
    url: 'https://cdn.example.com/x',
  });
  assert.ok(c.hashes.includes(SHA));
  assert.ok(c.hashes.includes('b'.repeat(64)));
  assert.ok(c.domains.includes('example.org'));
  assert.ok(c.domains.includes('dns.example.net'));
  assert.ok(c.urls.includes('https://cdn.example.com/x'));
});

test('readField prefers the flat dotted key, then walks nested objects', () => {
  assert.equal(readField({ 'a.b': 1, a: { b: 2 } }, 'a.b'), 1);
  assert.equal(readField({ a: { b: 2 } }, 'a.b'), 2);
  assert.equal(readField({ a: 'x' }, 'a.b'), undefined);
});

test('readField maps through arrays (native OCSF file.hashes[].value)', () => {
  const row = { file: { hashes: [{ algorithm_id: 1, value: 'c'.repeat(32) }, { algorithm_id: 3, value: SHA }] } };
  assert.deepEqual(readField(row, 'file.hashes.value'), ['c'.repeat(32), SHA]);
  assert.ok(artifactCandidates(row).hashes.includes(SHA));
  assert.equal(readField({ a: [{ x: 1 }] }, 'a.b'), undefined);
});

// Drift guard: every path the prevalence lookups key on must be extracted, or
// that artifact never reaches the Rarity view. Baseline keys come from the
// OCSF/UDM prevalence MVs (clickhouse/ocsf/init.sql `*_prevalence_source_ocsf_mv`,
// clickhouse/129); in-window paths from inWindowObservation.ts.
test('extracted fields cover every baseline and in-window lookup path', () => {
  const OCSF_BASELINE_HASH = ['file.hashes.sha256', 'process.file.hashes.sha256'];
  const OCSF_BASELINE_DOMAIN = ['dst_endpoint.hostname', 'query.hostname', 'url.hostname'];
  const hashFields = new Set<string>([...UDM_HASH_FIELDS, ...OCSF_HASH_FIELDS]);
  const domainFields = new Set<string>([...UDM_DOMAIN_FIELDS, ...OCSF_DOMAIN_FIELDS]);
  for (const p of [...OCSF_BASELINE_HASH, ...OCSF_HASH_PATHS, ...HASH_PATHS]) {
    assert.ok(hashFields.has(p), `hash path ${p} not extracted`);
  }
  for (const p of [...OCSF_BASELINE_DOMAIN, ...OCSF_DOMAIN_PATHS, ...DOMAIN_PATHS]) {
    assert.ok(domainFields.has(p), `domain path ${p} not extracted`);
  }
});

test('the same hostname under several OCSF fields is one candidate value', () => {
  // Dedup is per event downstream (seenInEvent); candidates may repeat but must
  // normalize to a single artifact.
  const c = artifactCandidates(CONDUIT_ROW);
  assert.equal(new Set(c.domains.map((d) => String(d).toLowerCase())).size, 1);
});
