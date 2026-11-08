// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
  draftFromSource, isStepPlan, parsePipelinePlan, pastedSampleEvents, planJson, recentSampleEvents, releasesFromVersions,
  serializePipeline, storedPlan, summaryFromSource, supportedStepKinds, tapEvents, IMPORTED_STEP_ID, PIPE_HEADER, PIPE_PLAN_BODY,
} from './pipeline-model';
import type { PipelineDraft } from './pipeline-types';
import type { LogSource, LogSourceVersion } from './api/types';

const draft: PipelineDraft = {
  name: 'Firewall', description: '', revision: 4,
  steps: [
    { id: 'parse-1', name: 'Parse JSON', kind: 'parse', enabled: true, condition: '', config: { format: 'json', field: 'message' } },
    { id: 'mask-1', name: 'Mask user', kind: 'mask', enabled: true, config: { fields: ['actor.user.name'], operation: 'hash', algorithm: 'sha256' } },
    { id: 'drop-1', name: 'Drop heartbeats', kind: 'filter', enabled: false, config: { predicate: '.event.action == "heartbeat"', action: 'drop' } },
  ],
};
const source = (parser_vrl: string): LogSource => ({
  id: 'lsrc_1', name: 'Firewall', description: '', namespace: 'default', timezone: 'UTC', source_type: 'firewall', parser_vrl,
  validated: true, deployed: true, deployed_at: '2026-10-09T09:00:00Z', enabled: true, stale_alert_enabled: false, stale_threshold_minutes: 60,
  source_parser_linked: false, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-09T10:00:00Z',
});

describe('stored plan format', () => {
  it('serializes exactly the header line, the JSON plan and the fixed two-line body', () => {
    const stored = serializePipeline(draft);
    const [header, ...body] = stored.split('\n');
    expect(header.startsWith('# nano-pipe-v2 ')).toBe(true);
    expect(body.join('\n')).toBe('# Processing plan compiled by Nano at publication.\nnano_pipe_plan_v2()');
    const plan = JSON.parse(header.slice('# nano-pipe-v2 '.length));
    expect(Object.keys(plan)).toEqual(['version', 'revision', 'steps']);
    expect(plan.version).toBe(2);
    expect(plan.revision).toBe(4);
    // `condition` is omitted when absent (serde skip_serializing_if) and keeps server field order.
    expect(Object.keys(plan.steps[1])).toEqual(['id', 'name', 'kind', 'enabled', 'config']);
    expect(Object.keys(plan.steps[0])).toEqual(['id', 'name', 'kind', 'enabled', 'condition', 'config']);
    expect(stored).toBe(`${PIPE_HEADER}${JSON.stringify(plan)}\n${PIPE_PLAN_BODY}`);
  });

  it('round trips through draftFromSource without changing a byte', () => {
    const stored = serializePipeline(draft);
    const loaded = draftFromSource(source(stored));
    expect(loaded.steps).toEqual(draft.steps);
    expect(loaded.revision).toBe(4);
    expect(serializePipeline(loaded)).toBe(stored);
    expect(isStepPlan(stored)).toBe(true);
  });

  it('imports plain VRL as one Advanced VRL step', () => {
    const loaded = draftFromSource(source('.message = downcase(string!(.message))'));
    expect(loaded.steps).toEqual([{ id: IMPORTED_STEP_ID, name: 'Existing parser', kind: 'vrl', enabled: true, config: { code: '.message = downcase(string!(.message))' } }]);
    expect(isStepPlan('.message = "x"')).toBe(false);
    expect(draftFromSource(source('')).steps[0].config).toEqual({ code: '.' });
  });

  it('treats an edited marker body or forged steps as plain VRL', () => {
    const stored = serializePipeline(draft);
    expect(parsePipelinePlan(stored + '\n.x = 1')).toBeNull();
    const forged = `${PIPE_HEADER}${JSON.stringify({ version: 2, revision: 1, steps: [{ id: '__proto__', name: 'x', kind: 'vrl', enabled: true, config: {} }] })}\n${PIPE_PLAN_BODY}`;
    expect(parsePipelinePlan(forged)).toBeNull();
    const dup = `${PIPE_HEADER}${JSON.stringify({ version: 2, revision: 1, steps: [draft.steps[0], draft.steps[0]] })}\n${PIPE_PLAN_BODY}`;
    expect(parsePipelinePlan(dup)).toBeNull();
  });

  it('refuses to serialize more than 50 steps or a step that cannot compile', () => {
    const many = { ...draft, steps: Array.from({ length: 51 }, (_, i) => ({ ...draft.steps[0], id: `s${i}` })) };
    expect(() => serializePipeline(many)).toThrow(/at most 50/);
    expect(() => serializePipeline({ ...draft, steps: [{ id: 'v', name: 'empty', kind: 'vrl', enabled: true, config: { code: ' ' } }] })).toThrow(/VRL/);
    // The unguarded form still produces a copyable plan.
    expect(storedPlan({ revision: 1, steps: [] }).startsWith(PIPE_HEADER)).toBe(true);
    expect(JSON.parse(planJson(draft))).toEqual({ version: 2, revision: 4, steps: draft.steps });
  });
});

describe('inventory and history', () => {
  it('summarizes plan sources and plain-VRL sources', () => {
    const plan = summaryFromSource(source(serializePipeline(draft)), 3, false);
    expect(plan).toMatchObject({ stepPlan: true, stepCount: 3, draftRevision: 4, activeRevision: 3, hasDraft: false });
    const vrl = summaryFromSource(source('.x = 1'));
    expect(vrl).toMatchObject({ stepPlan: false, stepCount: 1, hasDraft: true });
  });
  it('lists versions newest first', () => {
    const versions = [1, 3, 2].map((n) => ({ id: n * 10, log_source_id: 'lsrc_1', version_number: n, parser_vrl: '.', is_active: n === 3, created_at: `2026-10-0${n}T00:00:00Z`, change_reason: n === 3 ? 'publish' : '' })) as LogSourceVersion[];
    expect(releasesFromVersions(versions).map((release) => [release.revision, release.versionId, release.active])).toEqual([[3, 30, true], [2, 20, false], [1, 10, false]]);
  });
  it('enables every advertised step kind', () => {
    expect(supportedStepKinds(['parse', 'combine', 'bogus', 'vrl'])).toEqual(['parse', 'combine', 'vrl']);
  });
});

describe('browser-only preview inputs', () => {
  it('maps pipe-samples rows, tap events and pasted text', () => {
    expect(recentSampleEvents([{ message: 'a' }, 'not an object', { message: 'b' }], 20).map((event) => event.input)).toEqual([{ message: 'a' }, { message: 'b' }]);
    const tapped = tapEvents([{ event: { message: 'x' }, input: 'push:C0FFEE00-0000-4000-8000-000000000001' }, { event: { message: 'y' }, input: 'garbage' }]);
    expect(tapped[0].nanoInput).toBe('push:c0ffee00-0000-4000-8000-000000000001');
    expect(tapped[1].nanoInput).toBeUndefined();
    expect(pastedSampleEvents('one\n\ntwo').map((event) => event.input)).toEqual([{ message: 'one' }, { message: 'two' }]);
    expect(pastedSampleEvents('[{"a":1},"raw"]').map((event) => event.input)).toEqual([{ message: '{"a":1}' }, { message: 'raw' }]);
    expect(() => pastedSampleEvents(' ')).toThrow();
  });
});
