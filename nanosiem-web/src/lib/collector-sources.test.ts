// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2597: collector allowlist + alias rules mirror the API and the 9001680 guard. */
import { describe, expect, it } from 'vitest';
import {
  MAX_SOURCE_ALIASES_BYTES,
  aliasProblem,
  aliasesBySlug,
  aliasesBytes,
  collectorProtocols,
  collectorSelectionProblem,
  declaredSources,
  syncAliases,
} from './collector-sources';

describe('collector sources (NAN-2597)', () => {
  it('prefills vendor sourcetypes for newly allowlisted sources and keeps user edits', () => {
    const first = syncAliases({}, ['palo_alto_traffic']);
    expect(first).toEqual({ 'pan:traffic': 'palo_alto_traffic' });
    // The user removed the suggestion and added their own.
    const edited = { 'panos:traffic': 'palo_alto_traffic' };
    const next = syncAliases(edited, ['palo_alto_traffic', 'okta'], ['palo_alto_traffic']);
    expect(next).toEqual({ 'panos:traffic': 'palo_alto_traffic', 'OktaIM2:log': 'okta' });
    // A source leaving the allowlist takes its aliases with it.
    expect(syncAliases(next, ['okta'], ['palo_alto_traffic', 'okta'])).toEqual({ 'OktaIM2:log': 'okta' });
    expect(syncAliases({}, ['my_custom_app'])).toEqual({});
  });

  it('refuses what the server refuses', () => {
    const slugs = ['okta', 'palo_alto_traffic'];
    expect(aliasProblem('pan:traffic', 'palo_alto_traffic', {}, slugs)).toBeNull();
    expect(aliasProblem('a/b.c-d_e:f', 'okta', {}, slugs)).toBeNull();
    expect(aliasProblem('bad name', 'okta', {}, slugs)).toMatch(/A-Z/);
    expect(aliasProblem('x'.repeat(129), 'okta', {}, slugs)).toMatch(/1-128/);
    expect(aliasProblem('unknown', 'okta', {}, slugs)).toMatch(/reserved/);
    expect(aliasProblem('default', 'okta', {}, slugs)).toMatch(/reserved/);
    expect(aliasProblem('okta', 'palo_alto_traffic', {}, slugs)).toMatch(/already a source/);
    expect(aliasProblem('x', 'aws', {}, slugs)).toMatch(/not in the allowlist/);
    expect(aliasProblem('shared', 'okta', { shared: 'palo_alto_traffic' }, slugs)).toMatch(/already maps to palo_alto_traffic/);

    expect(collectorSelectionProblem([], {})?.field).toBe('sources');
    expect(collectorSelectionProblem(['okta', 'unknown'], {})?.message).toMatch(/implicit/);
    expect(collectorSelectionProblem(['okta', 'okta'], {})?.message).toMatch(/distinct/);
    expect(collectorSelectionProblem(slugs, { 'pan:traffic': 'palo_alto_traffic' })).toBeNull();
  });

  it('bounds the alias map at 16 KiB like the API', () => {
    const big: Record<string, string> = {};
    for (let i = 0; i < 200; i++) big[`${String(i).padStart(3, '0')}${'a'.repeat(125)}`] = 'okta';
    expect(aliasesBytes(big)).toBeGreaterThan(MAX_SOURCE_ALIASES_BYTES);
    expect(collectorSelectionProblem(['okta'], big)?.message).toMatch(/16384/);
    const fits = Object.fromEntries(Object.entries(big).slice(0, 100));
    expect(collectorSelectionProblem(['okta'], fits)).toBeNull();
  });

  it('offers only protocols every selected source is enrolled for', () => {
    const pa = { slug: 'palo_alto_traffic', protocols: ['hec' as const, 'nano_https' as const], enrolled: true };
    const otel = { slug: 'k8s', protocols: ['otlp_http' as const], enrolled: true };
    const rolling = { slug: 'my_app', protocols: [], enrolled: false };
    expect(collectorProtocols([pa])).toEqual(['hec', 'nano_https']);
    expect(collectorProtocols([pa, rolling])).toEqual(['hec', 'nano_https']);
    expect(collectorProtocols([pa, otel])).toEqual([]);
    expect(collectorProtocols([])).toEqual([]);
  });

  it('lists declared names like the server (slugs, then aliases)', () => {
    const aliases = { 'pan:traffic': 'palo_alto_traffic', 'OktaIM2:log': 'okta' };
    expect(declaredSources(['palo_alto_traffic', 'okta'], aliases)).toBe('palo_alto_traffic, okta, OktaIM2:log, pan:traffic');
    expect(aliasesBySlug(aliases, ['palo_alto_traffic', 'okta'])).toEqual([
      { slug: 'palo_alto_traffic', aliases: ['pan:traffic'] },
      { slug: 'okta', aliases: ['OktaIM2:log'] },
    ]);
  });
});
