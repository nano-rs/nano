// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5704: the /prevalence "Search events" pivot searches every column the
// OCSF prevalence baseline counted the artifact from, over the page's window;
// legacy UDM deployments keep their NAN-4903 pivot.
import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';

import { schemaFieldMap } from '@/lib/schema-fields';
import {
  PREVALENCE_SOURCE_FIELDS,
  prevalenceArtifactClass,
  prevalenceDrilldownFragment,
  prevalencePivotFilter,
  prevalencePivotFragment,
  type PrevalenceArtifactClass,
} from './pivot';

const SHA = 'd4a566ae1ebc4f198f6bfee9def3ba543ffd727678886f7ed0f69d8728864b7f';

// ---------------------------------------------------------------------------
// The column lists are pinned to the prevalence MVs themselves.
// ---------------------------------------------------------------------------

const repoUrl = (rel: string) => new URL(`../../../../${rel}`, import.meta.url);
const repoFile = (rel: string) => readFileSync(repoUrl(rel), 'utf8');
// A checkout that carries only nanosiem-web skips the schema pins.
const HAS_OCSF_SCHEMA = existsSync(repoUrl('clickhouse/ocsf/init.sql'));
const schemaIt = HAS_OCSF_SCHEMA ? it : it.skip;

const CLASSES: readonly PrevalenceArtifactClass[] = ['hash', 'domain', 'ip'];

/** Drop `uniqState(...)` (the host-count key, not an artifact source). */
function stripHostKey(stmt: string): string {
  let out = stmt;
  for (let i = out.indexOf('uniqState('); i >= 0; i = out.indexOf('uniqState(')) {
    let depth = 0;
    let j = i + 'uniqState'.length;
    for (; j < out.length; j++) {
      if (out[j] === '(') depth++;
      else if (out[j] === ')' && --depth === 0) break;
    }
    out = out.slice(0, i) + out.slice(j + 1);
  }
  return out;
}

const COLUMN_SHAPE: Record<PrevalenceArtifactClass, RegExp> = {
  hash: /\.hashes\./,
  domain: /hostname$/,
  ip: /\.ip$/,
};

/**
 * Every statement that defines a prevalence MV over `ocsf_logs` (CREATE or
 * ALTER … MODIFY QUERY, any view name, matched by the `(hash|domain|ip)_prevalence`
 * name or target table), keyed by view name, with the artifact columns it reads.
 */
function prevalenceProducers(sql: string): Map<string, { cls: PrevalenceArtifactClass; cols: Set<string> }> {
  const out = new Map<string, { cls: PrevalenceArtifactClass; cols: Set<string> }>();
  const clean = sql.replace(/--[^\n]*/g, '');
  for (const stmt of clean.split(';')) {
    const name = stmt.match(/(?:CREATE MATERIALIZED VIEW(?:\s+IF NOT EXISTS)?|ALTER TABLE)\s+nanosiem\.(\w+)/)?.[1];
    if (!name || !/FROM\s+nanosiem\.ocsf_logs\b/.test(stmt)) continue;
    const head = stmt.slice(0, stmt.search(/\bSELECT\b/));
    const cls = (name.match(/(hash|domain|ip)_prevalence/) ?? head.match(/(hash|domain|ip)_prevalence/))?.[1] as
      | PrevalenceArtifactClass
      | undefined;
    if (!cls) continue;
    const cols = new Set<string>();
    for (const [, col] of stripHostKey(stmt).matchAll(/`([^`]+)`/g)) if (COLUMN_SHAPE[cls].test(col)) cols.add(col);
    out.set(name, { cls, cols });
  }
  return out;
}

/** A hash MV reads `X.hashes.sha256`; the pivot reads its indexed `X.hashes.value` array. */
const pivotColumn = (col: string) => col.replace(/\.hashes\.sha256$/, '.hashes.value');

describe('prevalence pivot columns follow the prevalence MVs (NAN-5704)', () => {
  schemaIt('fresh install: every OCSF prevalence producer in init.sql', () => {
    const producers = prevalenceProducers(repoFile('clickhouse/ocsf/init.sql'));
    // 4 hash + 6 domain + 3 ip producers today: the scan really ran, and the
    // source-attributed (`*_prevalence_source_ocsf*_mv`) family is included.
    expect(producers.size).toBeGreaterThanOrEqual(13);
    expect([...producers.keys()].some((n) => n.includes('_source_ocsf'))).toBe(true);
    const read: Record<PrevalenceArtifactClass, Set<string>> = { hash: new Set(), domain: new Set(), ip: new Set() };
    for (const { cls, cols } of producers.values()) for (const c of cols) read[cls].add(pivotColumn(c));
    for (const cls of CLASSES) expect(new Set(PREVALENCE_SOURCE_FIELDS[cls]), cls).toEqual(read[cls]);
  });

  schemaIt('upgrade path: the latest migration definition of each producer reads the same columns', () => {
    const fresh = prevalenceProducers(repoFile('clickhouse/ocsf/init.sql'));
    const latest = new Map<string, { cls: PrevalenceArtifactClass; cols: Set<string> }>();
    const dir = 'clickhouse/ocsf/migrations';
    for (const mig of readdirSync(repoUrl(dir)).filter((f) => f.endsWith('.sql')).sort()) {
      for (const [name, def] of prevalenceProducers(repoFile(`${dir}/${mig}`))) latest.set(name, def);
    }
    expect(latest.size).toBeGreaterThanOrEqual(10);
    for (const [name, { cls, cols }] of latest) {
      for (const c of cols) expect(PREVALENCE_SOURCE_FIELDS[cls], `${name} reads ${c}`).toContain(pivotColumn(c));
      if (fresh.has(name)) expect(cols, name).toEqual(fresh.get(name)!.cols);
    }
  });

  schemaIt('each hash MV column is the sha256 entry of the indexed array the pivot filters', () => {
    const ddl = repoFile('clickhouse/ocsf/init.sql');
    for (const arr of PREVALENCE_SOURCE_FIELDS.hash) {
      const path = arr.replace(/\.hashes\.value$/, '');
      const event = path.split('.').map((p) => `\`${p}\``).join('.');
      // The array: lowercased hash values; the scalar: its algorithm_id 3 entry.
      expect(ddl).toContain(`arrayMap(x -> lower(x), arrayMap(x -> ifNull(toString(x), ''), event.${event}.\`hashes\`[].\`value\`)) AS \`${arr}\``);
      expect(ddl).toContain(`= 3, event.${event}.\`hashes\`[]).value), '')) AS \`${path}.hashes.sha256\``);
      expect(ddl).toMatch(new RegExp(`INDEX \\w+ \`${arr.replace(/\./g, '\\.')}\` TYPE bloom_filter`));
    }
  });
});

describe('prevalence pivot (NAN-5704)', () => {
  it('a process hash pivots to every indexed hash array, not only file.hashes', () => {
    expect(prevalencePivotFilter('hash_sha256', SHA)).toBe(
      `(file.hashes.value="${SHA}" OR process.file.hashes.value="${SHA}" OR actor.process.file.hashes.value="${SHA}")`,
    );
  });

  it('domains include DNS query and URL hostnames; IPs include the source side', () => {
    const d = prevalencePivotFilter('subdomain', 'evil.example.com');
    for (const col of ['dst_endpoint.hostname', 'query.hostname', 'url.hostname', 'http_request.url.hostname']) {
      expect(d).toContain(`${col}="evil.example.com"`);
    }
    const ip = prevalencePivotFilter('ip_address_private', '10.1.2.3');
    expect(ip).toBe('(dst_endpoint.ip="10.1.2.3" OR src_endpoint.ip="10.1.2.3")');
  });

  it('every artifact type maps to a class', () => {
    const cases: Array<[string, PrevalenceArtifactClass]> = [
      ['hash_md5', 'hash'],
      ['hash_sha256', 'hash'],
      ['hash_unknown', 'hash'],
      ['domain', 'domain'],
      ['subdomain', 'domain'],
      ['ip_address', 'ip'],
      ['ip_address_private', 'ip'],
    ];
    for (const [type, cls] of cases) expect(prevalenceArtifactClass(type), type).toBe(cls);
  });

  it('the filter stays a valid nPL term for hostile values', () => {
    const q = prevalencePivotFilter('domain', 'a" OR src_endpoint.ip=10.0.0.9');
    // Each OR branch is one `col='literal'` (nplLiteral switches delimiter):
    // the `"` stays inside the value and cannot break out.
    const terms = q.slice(1, -1).match(/[\w.]+='[^']*'/g) ?? [];
    expect(terms.every((t) => t.endsWith(`='a" OR src_endpoint.ip=10.0.0.9'`))).toBe(true);
    expect(terms).toHaveLength(PREVALENCE_SOURCE_FIELDS.domain.length);
    expect(terms.join(' OR ')).toBe(q.slice(1, -1));
  });

  it('carries the prevalence window into Search', () => {
    const frag = new URLSearchParams(prevalencePivotFragment('hash_sha256', SHA, '7d'));
    expect(frag.get('q')).toBe(prevalencePivotFilter('hash_sha256', SHA));
    expect(frag.get('time')).toBe('Last 7 days');
    expect(new URLSearchParams(prevalencePivotFragment('domain', 'x.com', '1h')).get('time')).toBe('Last hour');
    expect(new URLSearchParams(prevalencePivotFragment('domain', 'x.com', 'bogus')).get('time')).toBeNull();
  });
});

describe('prevalence drilldown by schema profile', () => {
  it('OCSF deployments get the multi-column pivot over the page window', () => {
    expect(prevalenceDrilldownFragment(schemaFieldMap('ocsf'), 'hash_sha256', SHA, '7d')).toBe(
      prevalencePivotFragment('hash_sha256', SHA, '7d'),
    );
  });

  it('legacy UDM deployments keep the NAN-4903 concept-column pivot unchanged', () => {
    const udm = schemaFieldMap('udm');
    expect(prevalenceDrilldownFragment(udm, 'hash_sha256', SHA, '7d')).toBe(`q=${encodeURIComponent(`file_hash="${SHA}"`)}`);
    expect(prevalenceDrilldownFragment(udm, 'ip_address', '8.8.8.8', '7d')).toBe(`q=${encodeURIComponent('dest_ip="8.8.8.8"')}`);
    expect(prevalenceDrilldownFragment(udm, 'domain', 'x.com', '7d')).toBe(`q=${encodeURIComponent('dest_host="x.com"')}`);
  });
});
