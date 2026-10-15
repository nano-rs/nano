// SPDX-License-Identifier: AGPL-3.0-or-later

import type { PipelineStep, PipelineStepKind } from '@/lib/pipeline-types';
import { safeRandomUUID } from '@/lib/uuid';

export const STEP_LABELS: Record<PipelineStepKind, string> = {
  rename: 'Rename field',
  remove: 'Remove field',
  set: 'Set field',
  redact: 'Redact fields',
  parse: 'Parse',
  fields: 'Field operations',
  mask: 'Mask or hash',
  split: 'Split events',
  combine: 'Combine or summarize',
  filter: 'Filter',
  sample: 'Sample',
  lookup: 'Lookup',
  dedupe: 'Dedupe',
  route: 'Route',
  vrl: 'Advanced VRL',
};

const DEFAULT_CONFIG: Record<PipelineStepKind, Record<string, unknown>> = {
  rename: { field: 'old', target: 'new' },
  remove: { field: 'field' },
  set: { field: 'field', value: '' },
  redact: { fields: ['user.email'], replacement: '[REDACTED]' },
  parse: { format: 'json', field: 'message' },
  fields: { operation: 'rename', field: 'old', target: 'new', value: '' },
  mask: {
    fields: ['user.email'],
    operation: 'replace',
    replacement: '[REDACTED]',
  },
  split: { field: '.items', as: '.item', keep: [], max: 50 },
  combine: {
    keys: ['src_endpoint.ip'],
    merge: {},
    maxEvents: 100,
    timeoutSec: 5,
    countField: 'unmapped.event_count',
  },
  filter: { predicate: '.event.action == "heartbeat"', action: 'drop' },
  sample: { ratio: 10, groupBy: 'message', exempt: '' },
  lookup: {
    table: 'lookup', version: '1',
    match: { key: 'message' }, outputs: { value: 'unmapped.lookup_value' },
    rows: [{ key: 'example', value: 'matched' }], missing: 'leave',
  },
  dedupe: { fields: ['message'], cacheEvents: 1000 },
  route: {
    mode: 'first', field: 'unmapped.pipe_route',
    routes: [{ label: 'matching', predicate: 'true', drop: false }], fallback: 'keep',
  },
  vrl: { code: '# Vector Remap Language\n', onError: 'pass' },
};

export function newPipelineStep(kind: PipelineStepKind): PipelineStep {
  return {
    id: safeRandomUUID(),
    name: STEP_LABELS[kind],
    kind,
    enabled: true,
    condition: '',
    config: structuredClone(DEFAULT_CONFIG[kind]),
  };
}
