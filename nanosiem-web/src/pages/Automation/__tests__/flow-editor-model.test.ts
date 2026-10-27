// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-4650 — drag rules for a new Condition from the palette.
import { describe, expect, test } from 'vitest';
import { ROOT, canDrop, serverFindings, toDoc, type DragItem } from '../flow-editor-model';

const pass = (id: string) => ({ id, value: { type: 'identity' } });
const newCond: DragItem = { kind: 'new', spec: { block: 'condition' }, label: 'Condition' };

const flat = () => toDoc({ value: { modules: [pass('a'), pass('b')] } }, 'f');
const withLoop = () => toDoc({ value: { modules: [pass('a'), { id: 'loop', value: { type: 'forloopflow', iterator: { type: 'expr', expr: 'x' }, modules: [pass('in')] } }] } }, 'f');
const withCond = () =>
  toDoc({ value: { modules: [pass('a'), { id: 'br', value: { type: 'branchone', branches: [{ expr: 'x = 1', modules: [pass('t')] }], default: [pass('e')] } }, pass('z')] } }, 'f');

describe('canDrop: new condition', () => {
  test('any root gap is ok when the flow has no condition', () => {
    const doc = flat();
    expect(canDrop(doc, newCond, { ref: ROOT, before: null })).toBe(true);
    expect(canDrop(doc, newCond, { ref: ROOT, before: 'a' })).toBe(true);
    expect(canDrop(doc, newCond, { ref: ROOT, before: 'b' })).toBe(true);
    expect(canDrop(toDoc({ value: { modules: [] } }, 'f'), newCond, { ref: ROOT, before: null })).toBe(true);
  });

  test('a second condition is refused anywhere', () => {
    const doc = withCond();
    expect(canDrop(doc, newCond, { ref: ROOT, before: null })).toBe(false);
    expect(canDrop(doc, newCond, { ref: ROOT, before: 'a' })).toBe(false);
  });

  test('inside a loop or a branch is refused', () => {
    expect(canDrop(withLoop(), newCond, { ref: { owner: 'loop', slot: 'modules' }, before: null })).toBe(false);
    expect(canDrop(withLoop(), newCond, { ref: { owner: 'loop', slot: 'modules' }, before: 'in' })).toBe(false);
    const doc = withCond();
    expect(canDrop(doc, newCond, { ref: { owner: 'br', slot: 0 }, before: null })).toBe(false);
    expect(canDrop(doc, newCond, { ref: { owner: 'br', slot: 'default' }, before: null })).toBe(false);
    // A parallel (branchall) lane, with no condition in the flow yet.
    const par = toDoc({ value: { modules: [{ id: 'all', value: { type: 'branchall', branches: [{ modules: [] }] } }] } }, 'f');
    expect(canDrop(par, newCond, { ref: ROOT, before: null })).toBe(true);
    expect(canDrop(par, newCond, { ref: { owner: 'all', slot: 0 }, before: null })).toBe(false);
  });

  test('moving an existing branch stays refused', () => {
    expect(canDrop(withCond(), { kind: 'move', id: 'br' }, { ref: ROOT, before: 'a' })).toBe(false);
  });

  test('other new blocks still drop inside branches', () => {
    expect(canDrop(withCond(), { kind: 'new', spec: { block: 'pass' }, label: 'Pass' }, { ref: { owner: 'br', slot: 0 }, before: null })).toBe(true);
  });
});

describe('serverFindings (NAN-4651)', () => {
  test('a "module `id`:" finding lands only on that step, not on ids inside the path', () => {
    const doc = toDoc({ value: { modules: [pass('hunt'), pass('user'), pass('name')] } }, 'f');
    const msg = 'module `hunt`: alert.user.name: a manual trigger has no alert; use an alert trigger or a run input';
    expect(serverFindings(msg, doc)).toEqual([{ step: 'hunt', message: msg }]);
    expect(serverFindings('flow uses user and name', doc).map((f) => f.step)).toEqual(['user', 'name']);
  });
});
