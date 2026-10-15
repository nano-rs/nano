// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import {
  CURATED_OCSF_FIELDS,
  curatedFieldsFor,
  rankFieldSuggestions,
  type RankableField,
} from './field-suggestion-ranking';

const universe = (...names: string[]) =>
  new Map<string, RankableField>(names.map((n) => [n, { value: n, category: 'System' }]));

const OCSF = universe(
  'metadata.event_code',
  'metadata.log_source',
  'metadata.uid',
  'src_endpoint.ip',
  'dst_endpoint.ip',
  'actor.user.name',
  'device.hostname',
  'process.name',
  'class_uid',
  'zeta.field',
);

describe('rankFieldSuggestions (NAN-3812)', () => {
  it('cold start: metadata.log_source leads, before metadata.event_code', () => {
    const ranked = rankFieldSuggestions({ partial: '', universe: OCSF, usage: null, curated: curatedFieldsFor(OCSF, []) });
    expect(ranked[0]).toMatchObject({ value: 'metadata.log_source', section: 'common' });
    const names = ranked.map((r) => r.value);
    expect(names.indexOf('metadata.log_source')).toBeLessThan(names.indexOf('metadata.event_code'));
    // Everything else follows, alphabetical.
    const rest = ranked.filter((r) => r.section === 'other').map((r) => r.value);
    expect(rest).toEqual([...rest].sort((a, b) => a.localeCompare(b)));
    expect(rest).toContain('metadata.event_code');
  });

  it('typing "m" still puts metadata.log_source first', () => {
    const ranked = rankFieldSuggestions({ partial: 'm', universe: OCSF, usage: null, curated: curatedFieldsFor(OCSF, []) });
    expect(ranked.map((r) => r.value)).toEqual(['metadata.log_source', 'metadata.event_code', 'metadata.uid']);
  });

  it('groups recent, then popular, then common, then the rest — each field once', () => {
    const ranked = rankFieldSuggestions({
      partial: '',
      universe: OCSF,
      usage: { recent: ['src_endpoint.ip'], popular: ['src_endpoint.ip', 'class_uid', 'process.name'] },
      curated: curatedFieldsFor(OCSF, []),
    });
    const sections = ranked.map((r) => r.section);
    expect(ranked[0]).toMatchObject({ value: 'src_endpoint.ip', section: 'recent' });
    expect(ranked.slice(1, 3).map((r) => [r.value, r.section])).toEqual([
      ['class_uid', 'popular'],
      ['process.name', 'popular'],
    ]);
    expect(ranked[3]).toMatchObject({ value: 'metadata.log_source', section: 'common' });
    // Section order never goes backwards.
    const order = ['recent', 'popular', 'common', 'other'];
    expect(sections.map((s) => order.indexOf(s))).toEqual([...sections.map((s) => order.indexOf(s))].sort());
    const names = ranked.map((r) => r.value);
    expect(new Set(names).size).toBe(names.length);
  });

  it('prefix filters inside every group', () => {
    const ranked = rankFieldSuggestions({
      partial: 'd',
      universe: OCSF,
      usage: { recent: ['src_endpoint.ip', 'dst_endpoint.ip'], popular: ['device.hostname'] },
      curated: curatedFieldsFor(OCSF, []),
    });
    expect(ranked.map((r) => [r.value, r.section])).toEqual([
      ['dst_endpoint.ip', 'recent'],
      ['device.hostname', 'popular'],
    ]);
  });

  it('caps recent at 5 and popular at 10', () => {
    const many = Array.from({ length: 30 }, (_, i) => `f${String(i).padStart(2, '0')}`);
    const u = universe(...many);
    const ranked = rankFieldSuggestions({
      partial: '',
      universe: u,
      usage: { recent: many.slice(0, 8), popular: many.slice(0, 20) },
      curated: [],
    });
    expect(ranked.filter((r) => r.section === 'recent')).toHaveLength(5);
    expect(ranked.filter((r) => r.section === 'popular')).toHaveLength(10);
  });

  it('drops usage fields the schema does not know, trusts them before it loads', () => {
    const usage = { recent: ['old_eval_name', 'src_endpoint.ip'], popular: [] };
    const known = rankFieldSuggestions({ partial: '', universe: OCSF, usage, curated: [] });
    expect(known.filter((r) => r.section === 'recent').map((r) => r.value)).toEqual(['src_endpoint.ip']);
    const cold = rankFieldSuggestions({ partial: '', universe: new Map(), universeComplete: false, usage, curated: [] });
    expect(cold.map((r) => r.value)).toEqual(['old_eval_name', 'src_endpoint.ip']);
  });
});

describe('curatedFieldsFor', () => {
  it('starts with metadata.log_source and filters to the tenant schema', () => {
    expect(CURATED_OCSF_FIELDS[0].value).toBe('metadata.log_source');
    expect(curatedFieldsFor(new Map(), [])).toBe(CURATED_OCSF_FIELDS);
    const curated = curatedFieldsFor(universe('metadata.log_source', 'src_endpoint.ip'), []).map((f) => f.value);
    expect(curated).toEqual(['metadata.log_source', 'src_endpoint.ip']);
  });

  it('keeps the legacy list on a UDM schema and honors an override', () => {
    const legacy = [{ value: 'src_ip' }];
    expect(curatedFieldsFor(universe('src_ip', 'user'), legacy)).toBe(legacy);
    const override = [{ value: 'time' }];
    expect(curatedFieldsFor(OCSF, legacy, override)).toBe(override);
  });
});
