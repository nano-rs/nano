// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4586 — the field catalog behind easy mode: condition round-trips,
// expression and JSON-key autocomplete, scope visibility, inputs checks.
import { describe, expect, test } from 'vitest';
import { toDoc } from '../flow-editor-model';
import {
  checkInputsJson,
  checkValue,
  completeExpression,
  describeCondition,
  formatEasyCondition,
  inputFields,
  jsonKeyContext,
  jsonKeyOptions,
  outerTimeModifiers,
  parseEasyCondition,
  sampleInputs,
  scopeFields,
  searchSkeleton,
} from '../soar-fields';

describe('easy conditions', () => {
  test('the three editor forms round-trip byte for byte', () => {
    for (const expr of ['flow_input.alert.severity = high', 'flow_input.alert.severity in [high, critical]', 'results.search.truncated', 'flow_input.case.previous_status = " padded"', 'flow_input.alert.severity in []']) {
      const c = parseEasyCondition(expr);
      expect(c, expr).not.toBeNull();
      expect(formatEasyCondition(c!)).toBe(expr);
    }
  });
  test('writes the existing expr strings', () => {
    expect(formatEasyCondition({ path: 'flow_input.alert.severity', op: 'is', values: ['high'] })).toBe('flow_input.alert.severity = high');
    expect(formatEasyCondition({ path: 'flow_input.alert.severity', op: 'one_of', values: ['high', 'critical'] })).toBe('flow_input.alert.severity in [high, critical]');
    expect(formatEasyCondition({ path: 'results.s.truncated', op: 'true', values: [] })).toBe('results.s.truncated');
  });
  test('anything the sentence cannot show exactly stays advanced', () => {
    for (const expr of ['flow_input.alert.severity == high', 'flow_input.alert.severity in [high,critical]', 'lower flow_input.alert.title', 'coalesce flow_input.a flow_input.b', 'secrets.KEY', 'flow_input.case.previous_status = "closed"', 'flow_input.case.previous_status = "a, b"', 'flow_input.x in ["a, b", c]']) {
      expect(parseEasyCondition(expr), expr).toBeNull();
    }
  });
  test('canvas sentence uses catalog labels', () => {
    const fields = inputFields('alert');
    expect(describeCondition('flow_input.alert.severity in [high, critical]', fields)).toBe('When Alert → Severity is one of high, critical');
    expect(describeCondition('lower flow_input.x', fields)).toBeNull();
  });
});

describe('autocomplete', () => {
  const doc = toDoc({ value: { modules: [
    { id: 'spread', value: { type: 'search', query: 'x', window: '24h', limit: 10 } },
    { id: 'each', value: { type: 'forloopflow', iterator: { type: 'expr', expr: 'flow_input.alert.tags' }, modules: [{ id: 'inner', value: { type: 'identity' } }] } },
    { id: 'after', value: { type: 'identity' } },
  ] } }, 'f');

  test('a partially typed path suggests catalog paths by prefix', () => {
    const fields = scopeFields(doc, 'alert', 'after', new Map());
    const text = 'flow_input.alert.sev';
    const c = completeExpression(text, text.length, fields)!;
    expect(c.from).toBe(0);
    expect(c.options[0].apply).toBe('flow_input.alert.severity');
    const ent = completeExpression('flow_input.alert.ent', 20, fields)!;
    expect(ent.options.map((o) => o.apply)).toEqual(expect.arrayContaining(['flow_input.alert.entities.host', 'flow_input.alert.entities.src_ip']));
    expect(ent.options.map((o) => o.apply)).toEqual(expect.arrayContaining(['flow_input.alert.entities.command_line', 'flow_input.alert.entities.domain']));
  });
  test('helpers for bare words, nothing inside string literals, word replaced in the middle', () => {
    const fields = inputFields('alert');
    expect(completeExpression('coa', 3, fields)!.options[0]).toMatchObject({ apply: 'coalesce ', kind: 'helper' });
    expect(completeExpression('join flow_input.alert.tags "fl', 30, fields)).toBeNull();
    const mid = completeExpression('lower flow_input.alert.ti x', 25, fields)!;
    expect(mid.from).toBe(6);
    expect(mid.to).toBe(25);
  });
  test('an alert path is offered only under an alert trigger (NAN-4651)', () => {
    const paths = (on: string) => scopeFields(doc, on, 'after', new Map()).map((f) => f.path);
    expect(paths('alert')).toContain('flow_input.alert.tags');
    for (const on of ['manual', 'case', 'case.triage_verdict', 'schedule']) {
      expect(paths(on).filter((p) => p.startsWith('flow_input.alert.'))).toEqual([]);
    }
  });
  test('scope follows compile visibility: earlier steps only, loop item only inside the loop', () => {
    const paths = (id: string) => scopeFields(doc, 'alert', id, new Map()).map((f) => f.path);
    expect(paths('spread')).not.toContain('results.spread.summary.count');
    expect(paths('each')).toContain('results.spread.summary.count');
    expect(paths('each')).not.toContain('flow_input.iter.value');
    expect(paths('inner')).toContain('flow_input.iter.value');
    expect(paths('after')).not.toContain('flow_input.iter.value');
    expect(paths('after')).toContain('run.case_id');
  });
});

describe('inputs', () => {
  test('sample payloads follow the trigger function shapes', () => {
    expect(sampleInputs('case.transitioned')).toEqual({ case: { id: expect.any(String), status: 'closed', previous_status: 'in_progress', event: 'closed' } });
    expect(Object.keys(sampleInputs('case.triage_verdict')).sort()).toEqual(['alert_ids', 'case', 'confidence', 'top_entities', 'verdict']);
  });
  test('the alert sample has the #7935 payload shape', () => {
    const a = (sampleInputs('alert') as { alert: Record<string, unknown> }).alert;
    expect(Object.keys(a).sort()).toEqual(['created_at', 'entities', 'id', 'kind', 'rule_id', 'rule_name', 'severity', 'tags', 'title']);
    expect(Object.keys(a.entities as object).sort()).toEqual(['command_line', 'dest_ip', 'domain', 'hash', 'host', 'process', 'src_ip', 'user']);
  });
  test('JSON checks: parse errors, unknown keys, wrong types and values', () => {
    expect(checkInputsJson('{', 'alert').issues[0].severity).toBe('error');
    const r = checkInputsJson('{"alert":{"severity":"urgent","tags":"x"},"foo":1}', 'alert');
    expect(r.issues.map((i) => i.message)).toEqual([
      '"foo" is not part of the Alert committed event.',
      'alert.severity should be one of informational, low, medium, high, critical.',
      'alert.tags should be a list.',
    ]);
    expect(checkInputsJson('{"anything":1}', 'manual').issues).toEqual([]);
  });
  test('JSON key autocomplete follows the enclosing object', () => {
    const text = '{"alert": {"sev';
    const k = jsonKeyContext(text, text.length)!;
    expect(k).toMatchObject({ path: ['alert'], partial: 'sev', quoted: true });
    expect(jsonKeyOptions('alert', k.path).map((o) => o.key)).toEqual(expect.arrayContaining(['severity', 'entities', 'rule_name']));
    const top = jsonKeyContext('{ ', 2)!;
    expect(jsonKeyOptions('case.triage_verdict', top.path).map((o) => o.key)).toEqual(['case', 'verdict', 'confidence', 'alert_ids', 'top_entities']);
    expect(jsonKeyContext('{"alert": "x', 12)).toBeNull();
  });
  test('typed free text', () => {
    // Conditions match exactly, so a range would never match: one address only.
    expect(checkValue('ip', '10.0.0.1')).toBeNull();
    expect(checkValue('ip', 'fe80::1')).toBeNull();
    expect(checkValue('ip', '10.0.0.0/8')).toMatch(/one IP address/);
    expect(checkValue('text', 'FIN-LT-0388')).toBeNull();
    expect(checkValue('ip', '999.1.1.1')).toMatch(/IP address/);
    expect(checkValue('number', 'abc')).toMatch(/number/);
    expect(checkValue('hash', 'd41d8cd98f00b204e9800998ecf8427e')).toBeNull();
    expect(checkValue('enum', 'urgent', ['low'])).toMatch(/one of/);
  });
});

describe('search step query (mirror of flow/search.rs)', () => {
  test('bindings become the quoted marker literal, with alert./steps. aliases', () => {
    expect(searchSkeleton('host={{alert.entities.host}} | stats count by {{ steps.s.x }}')).toEqual({
      skeleton: 'host="NANOSOARBOUNDLITERAL0" | stats count by "NANOSOARBOUNDLITERAL1"',
      paths: ['flow_input.alert.entities.host', 'results.s.x'],
    });
  });
  test('malformed bindings and the marker itself are rejected', () => {
    expect(searchSkeleton('host={{alert.host')).toEqual({ error: expect.stringMatching(/closing/) });
    expect(searchSkeleton('host=x}}')).toEqual({ error: expect.stringMatching(/Unmatched/) });
    expect(searchSkeleton('host={{alert.a-b}}')).toEqual({ error: expect.stringMatching(/not a field path/) });
    expect(searchSkeleton('NANOSOARBOUNDLITERAL0')).toEqual({ error: expect.stringMatching(/may not contain/) });
  });
  test('outer earliest=/latest= only: quotes, word boundaries and subsearches are ignored', () => {
    expect(outerTimeModifiers('error earliest=-1h | stats count')).toEqual(['earliest=-1h']);
    expect(outerTimeModifiers('LATEST=now host=x')).toEqual(['LATEST=now']);
    expect(outerTimeModifiers('msg="earliest=-1h" myearliest=1 a.latest=2')).toEqual([]);
    expect(outerTimeModifiers('x [search earliest=-1h y]')).toEqual([]);
  });
});
