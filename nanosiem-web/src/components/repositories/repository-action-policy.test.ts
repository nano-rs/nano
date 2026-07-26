// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';
import { QueryClient, QueryObserver } from '@tanstack/react-query';

import {
  parserApplyAccess,
  parserDiffAccess,
  parserImportAccess,
  repositoryQueryEnabled,
  ruleDiffAccess,
  ruleImportAccess,
  sourceInventoryAccess,
} from './repository-action-policy.ts';

const permissionCheck = (permissions: readonly string[]) => (permission: string) =>
  permissions.includes(permission) || permissions.includes('*');

async function queryExecutions(enabled: boolean): Promise<number> {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  let executions = 0;
  const observer = new QueryObserver(queryClient, {
    queryKey: ['repository-permission-probe', enabled],
    enabled,
    queryFn: async () => {
      executions += 1;
      return null;
    },
  });

  const unsubscribe = observer.subscribe(() => {});
  await new Promise<void>((resolve) => setImmediate(resolve));
  unsubscribe();
  queryClient.clear();
  return executions;
}

test('NAN-2157: rule imports use outcome and lifecycle capabilities', () => {
  const importAndCreate = permissionCheck([
    'rule_repositories:import',
    'detections:create',
  ]);
  assert.equal(
    ruleImportAccess(importAndCreate, [
      { outcome: 'create', mode: 'staging', ruleFormat: 'sigma' },
    ]).allowed,
    true,
  );
  assert.deepEqual(
    ruleImportAccess(importAndCreate, [
      { outcome: 'create', mode: 'live', ruleFormat: 'sigma' },
    ]).missing,
    ['detections:promote'],
  );
  assert.deepEqual(
    ruleImportAccess(importAndCreate, [
      {
        outcome: 'create',
        mode: 'staging',
        ruleFormat: 'nanosiem',
        rawContent: '---\ndetection_mode: realtime\n---\nsource_type=foo',
      },
    ]).missing,
    ['detections:promote'],
  );
  assert.deepEqual(
    ruleImportAccess(importAndCreate, [{ outcome: 'update' }]).missing,
    ['detections:edit'],
  );
  assert.equal(
    ruleImportAccess(permissionCheck(['rule_repositories:import']), [
      { outcome: 'skip' },
    ]).allowed,
    true,
  );
});

test('NAN-2157: parser imports add source_configs:edit only for dispatch effects', () => {
  const base = permissionCheck([
    'parser_repositories:import',
    'log_sources:create',
  ]);
  assert.equal(
    parserImportAccess(base, [{ kind: 'enrichment' }], ['http']).allowed,
    true,
  );
  assert.equal(
    parserImportAccess(base, [{ ingestionMethod: 'kafka' }], ['http']).allowed,
    true,
  );
  assert.deepEqual(
    parserImportAccess(base, [{ ingestionMethod: 'routed' }], ['http']).missing,
    ['source_configs:edit'],
  );
  assert.deepEqual(
    parserImportAccess(base, [{ ingestionMethod: 'kafka' }], null).missing,
    ['source_configs:edit'],
  );
});

test('NAN-2157: diff and apply policies match live-target routes', () => {
  assert.deepEqual(
    ruleDiffAccess(permissionCheck(['rule_repositories:view'])).missing,
    ['detections:view'],
  );
  assert.deepEqual(
    parserDiffAccess(permissionCheck(['parser_repositories:view'])).missing,
    ['log_sources:view'],
  );
  assert.deepEqual(
    parserApplyAccess(permissionCheck(['parsers:edit'])).missing,
    ['log_sources:edit'],
  );
  assert.deepEqual(
    parserApplyAccess(
      permissionCheck(['parsers:edit', 'log_sources:edit']),
      true,
    ).missing,
    ['log_sources:deploy'],
  );
});

test('NAN-2159/NAN-2160: source inventory never treats search:view as admission', () => {
  assert.equal(sourceInventoryAccess(permissionCheck(['search:view'])).allowed, false);
  assert.equal(sourceInventoryAccess(permissionCheck(['search:execute'])).allowed, true);
  assert.equal(sourceInventoryAccess(permissionCheck(['detections:view'])).allowed, true);
});

test('target-view permission prevents diff queries instead of producing a 403', async () => {
  const denied = parserDiffAccess(permissionCheck(['parser_repositories:view']));
  const allowed = parserDiffAccess(
    permissionCheck(['parser_repositories:view', 'log_sources:view']),
  );

  assert.equal(await queryExecutions(repositoryQueryEnabled(denied)), 0);
  assert.equal(await queryExecutions(repositoryQueryEnabled(allowed)), 1);
});
