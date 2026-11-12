// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5312: `OCSF_ASSET_SEED_FIELDS` and `primaryIdentityKind` hand-mirror the
// backend's entity field tables. No API exposes them, so this test parses the
// Rust source and fails when the two drift:
//   - nanosiem-core/src/schema/entities.rs: `ocsf_columns`,
//     `ocsf_indexed_column`, `udm_keys` (what `EntityKind::from_field_name`
//     accepts);
//   - nanosiem-core/src/search/query_processing/command_extraction.rs:
//     `canonical_entity_field` (the kinds `| asset field=` seeds from).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { OCSF_ASSET_SEED_FIELDS, primaryIdentityKind } from './asset-pivot';

const read = (rel: string) =>
  readFileSync(fileURLToPath(new URL(`../../../nanosiem-core/src/${rel}`, import.meta.url)), 'utf8');

/** Body of `fn <name>` up to its closing brace at column 0. */
function fnBody(src: string, name: string): string {
  const start = src.indexOf(`fn ${name}(`);
  expect(start, `fn ${name} must still exist`).toBeGreaterThanOrEqual(0);
  return src.slice(start, src.indexOf('\n}\n', start));
}

const strings = (list: string) => [...list.matchAll(/"([^"]+)"/g)].map((m) => m[1]);

const entities = read('schema/entities.rs');
const extraction = read('search/query_processing/command_extraction.rs');

/** EntityKind → canonical name, for the kinds `| asset` seeds from. */
const CANONICAL: Record<string, string> = Object.fromEntries(
  [...fnBody(extraction, 'canonical_entity_field').matchAll(/EntityKind::(\w+)\s*=>\s*Some\("([^"]+)"\)/g)].map(
    (m) => [m[1], m[2]],
  ),
);
const SEED_KINDS = Object.keys(CANONICAL);

function byKind(body: string, re: RegExp): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const m of body.matchAll(re)) {
    if (!SEED_KINDS.includes(m[1])) continue;
    const set = out.get(m[1]) ?? new Set<string>();
    for (const f of strings(m[2])) set.add(f);
    out.set(m[1], set);
  }
  return out;
}

const ocsfColumns = byKind(fnBody(entities, 'ocsf_columns'), /\(E::(\w+),[^)]*\)\s*=>\s*\{?\s*&\[([^\]]*)\]/g);
const indexed = byKind(fnBody(entities, 'ocsf_indexed_column'), /EntityKind::(\w+)\s*=>\s*Some\(("[^"]+")\)/g);
const udmKeys = byKind(fnBody(entities, 'udm_keys'), /EntityKind::(\w+)\s*=>\s*&\[([^\]]*)\]/g);

const BUCKET: Record<string, 'hostname' | 'ip' | 'user'> = {
  SrcHost: 'hostname',
  DestHost: 'hostname',
  SrcIp: 'ip',
  DestIp: 'ip',
  User: 'user',
};

describe('asset-pivot field lists track the backend entity tables', () => {
  it('parsed the backend tables', () => {
    expect(SEED_KINDS.sort()).toEqual(['DestHost', 'DestIp', 'SrcHost', 'SrcIp', 'User']);
    for (const k of SEED_KINDS) expect(ocsfColumns.get(k)?.size, k).toBeGreaterThan(0);
  });

  it('OCSF_ASSET_SEED_FIELDS = OCSF columns + unified columns + canonical names', () => {
    const expected = new Set<string>();
    for (const k of SEED_KINDS) {
      for (const f of ocsfColumns.get(k) ?? []) expected.add(f);
      for (const f of indexed.get(k) ?? []) expected.add(f);
      expected.add(CANONICAL[k]);
    }
    expect([...OCSF_ASSET_SEED_FIELDS].sort()).toEqual([...expected].sort());
  });

  it('primaryIdentityKind buckets every backend name of each seed kind', () => {
    for (const k of SEED_KINDS) {
      const names = [...(ocsfColumns.get(k) ?? []), ...(indexed.get(k) ?? []), ...(udmKeys.get(k) ?? [])];
      for (const f of names) expect(primaryIdentityKind(f), `${k}: ${f}`).toBe(BUCKET[k]);
    }
  });
});
