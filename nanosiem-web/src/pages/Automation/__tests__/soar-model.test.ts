// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4540 — pure view-model rules for the Automation workspace.
import { describe, expect, test } from 'vitest';
import {
  actionIndex,
  actionsForEntity,
  bucketRuns,
  capabilityMatrix,
  countNodes,
  decisionBlock,
  entityKindForInput,
  flowGraph,
  flowLine,
  formatDuration,
  inputTargets,
  reasonRequired,
  runOutcome,
  stepSpans,
  utf8Bytes,
} from '../soar-model';
import { approval, catalog, connection, flow, pack, run, runDetail } from './fixtures';

describe('runOutcome', () => {
  test('maps statuses and treats an ambiguous step as unknown', () => {
    expect(runOutcome(run({ status: 'suspended' }))).toBe('waiting');
    expect(runOutcome(run({ status: 'succeeded' }))).toBe('ok');
    const detail = runDetail();
    detail.steps[0].status = 'ambiguous';
    expect(runOutcome(detail, detail.steps)).toBe('unknown');
  });
});

describe('decisionBlock mirrors the server refusals', () => {
  const ctx = { userId: 'me', canApprove: true, demo: false };
  test('open approval for another requester is decidable', () => {
    expect(decisionBlock(approval(), ctx)).toBeNull();
  });
  test('blocks', () => {
    expect(decisionBlock(approval({ status: 'approved' }), ctx)).toBe('Already decided');
    expect(decisionBlock(approval({ expires_at: new Date(Date.now() - 1000).toISOString() }), ctx)).toBe('Expired');
    expect(decisionBlock(approval(), { ...ctx, demo: true })).toBe('Read-only demo');
    expect(decisionBlock(approval(), { ...ctx, canApprove: false })).toBe('Requires soar:approve');
    expect(decisionBlock(approval({ requested_by: 'me' }), ctx)).toMatch(/another approver/);
  });
  test('note required only on the configured choice', () => {
    const a = approval({ requested_action: { options: ['a', 'b'], note_required_on: 'b' } });
    expect(reasonRequired(a, 'a')).toBe(false);
    expect(reasonRequired(a, 'b')).toBe(true);
    expect(utf8Bytes('é')).toBe(2);
  });
});

describe('entities and the verb palette', () => {
  test('input kinds from type, then name', () => {
    expect(entityKindForInput('target', 'ip')).toBe('ip');
    expect(entityKindForInput('hostname')).toBe('host');
    expect(entityKindForInput('user_email', 'email')).toBe('user');
    expect(entityKindForInput('sha256')).toBe('hash');
    expect(entityKindForInput('note')).toBe('value');
  });
  test('palette lists installed actions accepting the kind, read first, blocked last', () => {
    const choices = actionsForEntity('host', catalog(), [connection()]);
    expect(choices.map((c) => c.action.name)).toEqual(['get_host', 'contain_host']);
    expect(choices.every((c) => c.blocked === null)).toBe(true);
    const none = actionsForEntity('host', catalog(), []);
    expect(none.every((c) => c.blocked === 'No connection')).toBe(true);
    expect(actionsForEntity('host', catalog([pack({ installed: false })]), [connection()])).toEqual([]);
  });
  test('capability matrix marks covered kinds', () => {
    const m = capabilityMatrix(catalog());
    expect(m.rows.find((r) => r.kind === 'host')?.covered).toBe(true);
    expect(m.rows.find((r) => r.kind === 'ip')?.covered).toBe(false);
  });
  test('inputTargets keeps scalar inputs only', () => {
    const t = inputTargets({ hostname: 'ws-1', opts: { a: 1 }, tags: ['x', 'y'] });
    expect(t).toEqual([
      { name: 'hostname', value: 'ws-1', kind: 'host' },
      { name: 'tags', value: 'x, y', kind: 'value' },
    ]);
  });
});

describe('flow graph', () => {
  test('parses modules and line stops', () => {
    const g = flowGraph(flow().definition);
    expect(countNodes(g.nodes)).toBe(3);
    expect(flowLine(g.nodes, actionIndex(catalog()))).toEqual(['read', 'gate', 'destructive']);
  });
  test('branches and junk input', () => {
    const g = flowGraph({
      value: {
        modules: [
          { id: 'b', value: { type: 'branchone', branches: [{ expr: 'x > 1', modules: [{ id: 'n', value: { type: 'identity' } }] }], default: [] } },
        ],
      },
    });
    expect(g.nodes[0].branches.map((b) => b.label)).toEqual(['x > 1', 'default']);
    expect(countNodes(g.nodes)).toBe(2);
    expect(flowGraph(null).nodes).toEqual([]);
    expect(flowGraph({ value: { modules: 'nope' } }).nodes).toEqual([]);
  });
});

describe('time helpers', () => {
  test('bucketRuns counts loaded runs into 48 buckets', () => {
    const now = Date.parse('2026-10-25T12:10:00Z');
    const b = bucketRuns(
      [
        run({ created_at: '2026-10-25T12:05:00Z', status: 'failed' }),
        run({ created_at: '2026-10-25T11:40:00Z' }),
        run({ created_at: '2026-10-20T00:00:00Z' }),
      ],
      now,
    );
    expect(b).toHaveLength(48);
    expect(b.reduce((n, x) => n + x.ok + x.fail + x.wait + x.run, 0)).toBe(2);
    expect(b[b.length - 1].fail).toBe(1);
  });
  test('stepSpans are run-relative', () => {
    const d = runDetail();
    const { spans, total } = stepSpans(d.steps);
    expect(spans[0].start).toBe(0);
    expect(total).toBe(spans[0].duration);
  });
  test('formatDuration never shows 60s', () => {
    expect(formatDuration(119_600)).toBe('2m 0s');
    expect(formatDuration(59_700)).toBe('1m 0s');
    expect(formatDuration(65_000)).toBe('1m 5s');
    expect(formatDuration(5_000)).toBe('5.0s');
    expect(formatDuration(42_400)).toBe('42s');
    expect(formatDuration(3_725_000)).toBe('1h 2m');
  });
});
