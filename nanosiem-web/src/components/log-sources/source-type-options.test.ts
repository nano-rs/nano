// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import type { LogSource } from '@/lib/api';
import {
  buildSourceTypeOptions,
  findSelectedOption,
  optionMatchesSearch,
} from './source-type-options.ts';

// Minimal shape the option builder reads.
const ls = (name: string, source_type: string, match_values: string[] = []): LogSource =>
  ({ name, source_type, match_values }) as unknown as LogSource;

test('NAN-1916: one option per parser — match_values do not each get a row', () => {
  const options = buildSourceTypeOptions([
    ls('LimaCharlie EDR', 'limacharlie', ['limacharlie', 'lima_charlie', 'lc_sensor', 'lc_edr']),
    ls('Windows Event Log', 'windows_event', ['windows_event', 'winlogbeat', 'windows']),
  ]);
  assert.equal(options.length, 2);
  assert.deepEqual(
    options.map((o) => o.sourceType),
    ['limacharlie', 'windows_event']
  );
  // Aliases retained (minus the canonical) for search/selection, not as rows.
  const lima = options.find((o) => o.sourceType === 'limacharlie');
  assert.deepEqual(lima?.aliases, ['lima_charlie', 'lc_sensor', 'lc_edr']);
});

test('routed / vector transport sentinels are filtered out', () => {
  const options = buildSourceTypeOptions([
    ls('GCP Audit Log', 'gcp_audit', ['gcp_audit', 'gcp_audit_log', 'cloudaudit']),
    ls('Some Routed Feed', 'routed'),
    ls('Some Vector Feed', 'vector'),
  ]);
  assert.deepEqual(
    options.map((o) => o.sourceType),
    ['gcp_audit']
  );
});

test('duplicate source_types collapse to a single option', () => {
  const options = buildSourceTypeOptions([
    ls('A', 'foo', ['foo', 'bar']),
    ls('B', 'foo', ['foo', 'baz']),
  ]);
  assert.equal(options.length, 1);
  assert.equal(options[0].parserName, 'A');
});

test('findSelectedOption resolves a value stored on an alias (no "no parser" flash)', () => {
  const options = buildSourceTypeOptions([
    ls('LimaCharlie EDR', 'limacharlie', ['limacharlie', 'lc_edr']),
  ]);
  assert.equal(findSelectedOption(options, 'lc_edr')?.parserName, 'LimaCharlie EDR');
  assert.equal(findSelectedOption(options, 'limacharlie')?.parserName, 'LimaCharlie EDR');
  assert.equal(findSelectedOption(options, 'nope'), undefined);
  assert.equal(findSelectedOption(options, ''), undefined);
});

test('stamps a routable value when declared source_type is not among match_values', () => {
  // The router matches on match_values only. If the declared source_type isn't
  // one of them, stamping it would never route — so the primary match_value is
  // used as the canonical, and the declared source_type stays resolvable.
  const [opt] = buildSourceTypeOptions([ls('Weird Parser', 'foo', ['bar', 'baz'])]);
  assert.equal(opt.sourceType, 'bar'); // routable canonical, not "foo"
  assert.ok(opt.aliases.includes('baz'));
  assert.ok(opt.aliases.includes('foo')); // declared source_type still resolves
  const options = [opt];
  assert.equal(findSelectedOption(options, 'foo')?.parserName, 'Weird Parser');
  assert.equal(findSelectedOption(options, 'baz')?.parserName, 'Weird Parser');
});

test('empty match_values falls back to the declared source_type', () => {
  const [opt] = buildSourceTypeOptions([ls('Bare', 'bare_type', [])]);
  assert.equal(opt.sourceType, 'bare_type');
  assert.deepEqual(opt.aliases, []);
});

test('optionMatchesSearch matches source_type, parser name, and aliases', () => {
  const [opt] = buildSourceTypeOptions([
    ls('LimaCharlie EDR', 'limacharlie', ['limacharlie', 'lc_edr']),
  ]);
  assert.equal(optionMatchesSearch(opt, ''), true);
  assert.equal(optionMatchesSearch(opt, 'lima'), true); // source_type
  assert.equal(optionMatchesSearch(opt, 'charlie'), true); // parser name
  assert.equal(optionMatchesSearch(opt, 'lc_edr'), true); // alias
  assert.equal(optionMatchesSearch(opt, 'kafka'), false);
});
