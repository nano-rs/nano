// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  filterTechniqueGroup,
  summarizeTechniqueCoverage,
  techniqueMatchesFilters,
  tierFor,
} from '../src/components/mitre/types.ts';
import {
  invalidateMitreQueries,
  mitreAuthScope,
  mitreQueryKeys,
  normalizeMitreFilter,
} from '../src/hooks/mitre-query-keys.ts';

const liveRule = {
  id: 'rule-live',
  name: 'PowerShell execution',
  severity: 'high',
  mode: 'alerting',
  source: 'windows_sysmon',
};

const parent = {
  technique_id: 'T1059',
  technique_name: 'Command and Scripting Interpreter',
  is_subtechnique: false,
  tactic_ids: ['TA0002'],
  rule_count: 1,
  coverage_level: 'low',
  rules: [liveRule],
  data_sources: [{ id: 'process', name: 'Process Creation', connected: true }],
};

const child = {
  technique_id: 'T1059.001',
  technique_name: 'PowerShell',
  is_subtechnique: true,
  parent_id: 'T1059',
  tactic_ids: ['TA0002'],
  rule_count: 0,
  coverage_level: 'none',
  rules: [],
  data_sources: [{ id: 'powershell', name: 'PowerShell Logs', connected: false }],
};

test('covered parent does not cover its uncovered child', () => {
  const stats = summarizeTechniqueCoverage([parent, child]);

  assert.equal(stats.total, 2);
  assert.equal(stats.covered, 1);
  assert.equal(stats.percentage, 50);
  assert.deepEqual(stats.gaps.map((technique) => technique.technique_id), ['T1059.001']);
  assert.equal(tierFor(parent), 'partial');
  assert.equal(tierFor(child), 'gap');
});

test('filters evaluate a sub-technique independently from its parent', () => {
  const filters = {
    q: 'powershell',
    status: new Set(['live']),
    platforms: new Set(['windows_sysmon']),
    gapOnly: false,
  };

  assert.equal(techniqueMatchesFilters(parent, filters), true);
  assert.equal(techniqueMatchesFilters(child, filters), false);
  assert.equal(
    techniqueMatchesFilters(child, { ...filters, status: new Set(), platforms: new Set() }),
    true,
  );

  const childSearch = { ...filters, status: new Set(), platforms: new Set() };
  const unrelatedParent = { ...parent, technique_name: 'Unrelated parent', rules: [] };
  const group = filterTechniqueGroup(unrelatedParent, [child], childSearch);
  assert.equal(group.parentMatches, false);
  assert.equal(group.visible, true);
  assert.deepEqual(group.subs.map((technique) => technique.technique_id), ['T1059.001']);
});

test('query keys are auth scoped and successful sync invalidates the MITRE family', async () => {
  const token = (jti) => {
    const payload = Buffer.from(JSON.stringify({ sub: 'user-1', jti })).toString('base64url');
    return `header.${payload}.signature`;
  };
  const firstScope = mitreAuthScope('user-1', token('session-1'));
  const secondScope = mitreAuthScope('user-1', token('session-2'));

  assert.notEqual(firstScope, secondScope);
  assert.notDeepEqual(mitreQueryKeys.catalog(firstScope), mitreQueryKeys.catalog(secondScope));
  assert.deepEqual(normalizeMitreFilter([' HIGH ', 'critical', 'high']), ['critical', 'high']);

  let invalidated;
  await invalidateMitreQueries({
    invalidateQueries: ({ queryKey }) => {
      invalidated = queryKey;
    },
  });
  assert.deepEqual(invalidated, mitreQueryKeys.all);
});
