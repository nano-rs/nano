// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  type RequiredDataSource,
  type TechniqueCoverage,
  readinessLabel,
  readinessOf,
  tierFor,
} from './types.ts';

function uncoveredTechnique(dataSource: RequiredDataSource): TechniqueCoverage {
  return {
    technique_id: 'T1059',
    technique_name: 'Command and Scripting Interpreter',
    is_subtechnique: false,
    tactic_ids: ['TA0002'],
    rule_count: 0,
    coverage_level: 'none',
    rules: [],
    data_sources: [dataSource],
  };
}

test('rule-only source stays unknown and cannot create a hot gap', () => {
  const source: RequiredDataSource = {
    id: 'process_process_creation',
    name: 'Process: Process Creation',
    mapping_known: true,
    configured: false,
    readiness: 'unknown',
    connected: false,
  };

  assert.equal(readinessOf(source), 'unknown');
  assert.equal(readinessLabel(source), 'not configured');
  assert.equal(tierFor(uncoveredTechnique(source)), 'gap');
});

test('unmapped ATT&CK source remains unknown instead of claiming missing configuration', () => {
  const source: RequiredDataSource = {
    id: 'future_component',
    name: 'Unmapped Telemetry: Future Component',
    mapping_known: false,
    configured: false,
    readiness: 'unknown',
    connected: false,
  };

  assert.equal(readinessLabel(source), 'unknown');
  assert.equal(tierFor(uncoveredTechnique(source)), 'gap');
});

test('configured idle source is visibly idle but not a hot gap', () => {
  const source: RequiredDataSource = {
    id: 'process_process_creation',
    name: 'Process: Process Creation',
    configured: true,
    readiness: 'stale',
    last_seen_at: null,
    connected: false,
  };

  assert.equal(readinessLabel(source), 'idle');
  assert.equal(tierFor(uncoveredTechnique(source)), 'gap');
});

test('stale last-seen source remains a normal gap', () => {
  const source: RequiredDataSource = {
    id: 'process_process_creation',
    name: 'Process: Process Creation',
    configured: true,
    readiness: 'stale',
    last_seen_at: '2026-07-10T08:00:00Z',
    connected: false,
  };

  assert.equal(readinessLabel(source), 'stale');
  assert.equal(tierFor(uncoveredTechnique(source)), 'gap');
});

test('actively ingesting source creates a hot gap', () => {
  const source: RequiredDataSource = {
    id: 'process_process_creation',
    name: 'Process: Process Creation',
    configured: true,
    readiness: 'active',
    last_seen_at: '2026-07-10T11:58:00Z',
    connected: true,
  };

  assert.equal(readinessLabel(source), 'active');
  assert.equal(tierFor(uncoveredTechnique(source)), 'hot-gap');
});

test('unavailable ingestion health is unknown and cannot create a hot gap', () => {
  const source: RequiredDataSource = {
    id: 'process_process_creation',
    name: 'Process: Process Creation',
    configured: true,
    readiness: 'unknown',
    connected: false,
  };

  assert.equal(readinessLabel(source), 'unknown');
  assert.equal(tierFor(uncoveredTechnique(source)), 'gap');
});

test('readiness takes precedence over a contradictory legacy connected flag', () => {
  const source: RequiredDataSource = {
    id: 'process_process_creation',
    name: 'Process: Process Creation',
    configured: true,
    readiness: 'stale',
    connected: true,
  };

  assert.equal(readinessOf(source), 'stale');
  assert.equal(tierFor(uncoveredTechnique(source)), 'gap');
});
