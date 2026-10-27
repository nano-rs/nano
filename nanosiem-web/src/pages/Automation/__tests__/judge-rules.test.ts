// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4660 — judge authoring rules mirror the enterprise SOAR backend's soar/flow/judge.rs.
import { describe, expect, test } from 'vitest';
import { evidencePath, judgeErrors, labelProblem, ttlSecs } from '../judge-rules';
import { makeModule, toDoc } from '../flow-editor-model';
import { judgeScopeFindings, scopeFields } from '../soar-fields';

const ok = { type: 'judge', question: 'Bad?', labels: ['malicious', 'benign'], evidence: ['flow_input.alert.severity'], token_cap: 2000, cache_ttl: '6h' };

describe('judge rules', () => {
  test('cache TTL: positive seconds or hours, at most 24h', () => {
    expect(ttlSecs('6h')).toBe(21_600);
    expect(ttlSecs('90s')).toBe(90);
    expect(ttlSecs('24h')).toBe(86_400);
    for (const bad of ['25h', '0h', '0s', '30m', '6', '1.5h', ' 6h', '86401s']) expect(ttlSecs(bad), bad).toBeNull();
  });
  test('labels: ASCII word chars, ≤64, unknown reserved, unique ignoring case', () => {
    expect(labelProblem('needs_review')).toBeNull();
    expect(labelProblem('needs-review')).toBeNull();
    expect(labelProblem('Unknown')).toMatch(/reserved/);
    expect(labelProblem('a b')).toMatch(/letters/);
    expect(labelProblem('x'.repeat(65))).toMatch(/longer/);
    expect(labelProblem('Yes', ['yes'])).toMatch(/already/);
  });
  test('evidence paths: aliases normalize, other roots are refused', () => {
    expect(evidencePath('alert.severity')).toBe('flow_input.alert.severity');
    expect(evidencePath('steps.spread.summary')).toBe('results.spread.summary');
    expect(evidencePath('{{ run.id }}')).toBe('run.id');
    expect(evidencePath('secrets.x')).toBeNull();
    expect(evidencePath('results.a[0]')).toBeNull();
  });
  test('module checks: the valid example passes; each bound is reported', () => {
    expect(judgeErrors(ok)).toEqual([]);
    expect(judgeErrors({ ...ok, question: ' ' })).toEqual(['Question is required']);
    expect(judgeErrors({ ...ok, question: 'x'.repeat(2049) })).toEqual(['Question is longer than 2048 bytes']);
    expect(judgeErrors({ ...ok, labels: ['yes'] })).toEqual(['At least 2 labels are required']);
    expect(judgeErrors({ ...ok, evidence: [] })).toEqual(['Pick at least one evidence field']);
    expect(judgeErrors({ ...ok, evidence: Array.from({ length: 33 }, (_, i) => `run.f${i}`) })).toEqual(['At most 32 evidence fields']);
    expect(judgeErrors({ ...ok, token_cap: 0 })).toHaveLength(1);
    expect(judgeErrors({ ...ok, token_cap: 8001 })).toHaveLength(1);
    expect(judgeErrors({ ...ok, cache_ttl: '2d' })).toHaveLength(1);
    // Server defaults apply when the optional fields are absent.
    const { token_cap: _c, cache_ttl: _t, ...bare } = ok;
    void _c; void _t;
    expect(judgeErrors(bare)).toEqual([]);
  });
  test('makeModule: defaults match the server and only need question + evidence', () => {
    const m = makeModule({ block: 'judge' }, { index: new Map(), connections: [] }, new Set());
    expect(m.value).toEqual({ type: 'judge', question: '', labels: ['yes', 'no'], evidence: [], token_cap: 2000, cache_ttl: '6h' });
    expect(judgeErrors({ ...m.value, question: 'Bad?', evidence: ['run.id'] })).toEqual([]);
  });
  test('scope findings: alert evidence needs an alert trigger; results need an earlier step', () => {
    const doc = toDoc({ value: { modules: [
      { id: 'j', value: { ...ok, evidence: ['alert.severity', 'results.later.verdict'] } },
      { id: 'later', value: { type: 'identity' } },
    ] } }, 'f');
    expect(judgeScopeFindings(doc, 'alert').map((f) => f.message)).toEqual(['Evidence results.later.verdict: step later has not run before this step']);
    expect(judgeScopeFindings(doc, 'manual').map((f) => f.message)).toEqual([
      'Evidence alert.severity: a manual trigger has no alert; use an alert trigger or a run input',
      'Evidence results.later.verdict: step later has not run before this step',
    ]);
  });
  test('a later condition can branch on the verdict, with the labels plus unknown', () => {
    const doc = toDoc({ value: { modules: [{ id: 'j', value: ok }, { id: 'p', value: { type: 'identity' } }] } }, 'f');
    const verdict = scopeFields(doc, 'alert', 'p', new Map()).find((f) => f.path === 'results.j.verdict');
    expect(verdict?.values).toEqual(['malicious', 'benign', 'unknown']);
  });
});
