// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — pure editing model for the flow editor (port of the mock's
 * FlowEditor3 step list onto the real Windmill-subset definition).
 *
 * The definition stays the stored JSON tree. Every operation clones it and
 * edits modules in place, so fields the editor does not know about survive a
 * round-trip (the backend denies unknown fields; we never add any).
 *
 * Containers: the root module list, a loop's `modules`, each `branchone`
 * branch, its `default`, and each `branchall` branch.
 */
import type { SoarConnection, SoarFlowTrigger } from '@/lib/api/soar';
import type { Effect, IndexedAction } from './soar-model';
import { asEffect, lookupAction } from './soar-model';
import { JUDGE, judgeErrors } from './judge-rules';

/** Backend limits (enterprise SOAR backend, soar/flow/mod.rs). */
export const LIMITS = { modules: 64, depth: 4, iterations: 100, parallelism: 4, activeSecs: 900, wallSecs: 86_400 } as const;

export type Json = Record<string, unknown>;
export interface RawModule extends Json {
  id: string;
  summary?: string;
  value: Json;
}
export interface FlowDoc extends Json {
  summary: string;
  description: string;
  value: Json & { modules: RawModule[] };
}

export type Slot = 'modules' | 'default' | number;
export interface ContainerRef {
  /** Owning module id; null for the root list. */
  owner: string | null;
  slot: Slot;
}
export const ROOT: ContainerRef = { owner: null, slot: 'modules' };
export interface DropAt {
  ref: ContainerRef;
  /** Insert before this module id; null appends. */
  before: string | null;
}

export function refKey(ref: ContainerRef): string {
  return ref.owner === null ? 'root' : `${ref.owner}:${ref.slot}`;
}

function rec(v: unknown): Json | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : null;
}
function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

/** Normalize any stored definition into an editable document. */
export function toDoc(definition: unknown, fallbackSummary: string): FlowDoc {
  const d = structuredClone(rec(definition) ?? {}) as Json;
  const value = rec(d.value) ?? {};
  const modules = Array.isArray(value.modules) ? value.modules : [];
  return {
    ...d,
    summary: typeof d.summary === 'string' ? d.summary : fallbackSummary,
    description: typeof d.description === 'string' ? d.description : '',
    value: { ...value, modules: modules.filter((m): m is RawModule => !!rec(m) && typeof (m as Json).id === 'string' && !!rec((m as Json).value)) },
  } as FlowDoc;
}

export function typeOf(m: RawModule): string {
  return str(m.value.type);
}

/** Child lists of one module, with their container refs. */
export function childLists(m: RawModule): Array<{ ref: ContainerRef; list: RawModule[]; label: string }> {
  const v = m.value;
  const out: Array<{ ref: ContainerRef; list: RawModule[]; label: string }> = [];
  const t = typeOf(m);
  if (t === 'forloopflow') {
    if (!Array.isArray(v.modules)) v.modules = [];
    out.push({ ref: { owner: m.id, slot: 'modules' }, list: v.modules as RawModule[], label: 'for each' });
  } else if (t === 'branchone' || t === 'branchall') {
    const branches = Array.isArray(v.branches) ? (v.branches as Json[]) : [];
    branches.forEach((b, i) => {
      if (!Array.isArray(b.modules)) b.modules = [];
      out.push({ ref: { owner: m.id, slot: i }, list: b.modules as RawModule[], label: str(b.summary) || str(b.expr) || `branch ${i + 1}` });
    });
    if (t === 'branchone') {
      if (!Array.isArray(v.default)) v.default = [];
      out.push({ ref: { owner: m.id, slot: 'default' }, list: v.default as RawModule[], label: 'else' });
    }
  }
  return out;
}

export interface Located {
  mod: RawModule;
  ref: ContainerRef;
  index: number;
  /** 1 for root modules. */
  depth: number;
  /** Owners from the root down to (not including) this module. */
  ancestors: RawModule[];
}

export function walk(doc: FlowDoc, fn: (loc: Located) => void) {
  const visit = (list: RawModule[], ref: ContainerRef, depth: number, ancestors: RawModule[]) => {
    list.forEach((mod, index) => {
      fn({ mod, ref, index, depth, ancestors });
      for (const c of childLists(mod)) visit(c.list, c.ref, depth + 1, [...ancestors, mod]);
    });
  };
  visit(doc.value.modules, ROOT, 1, []);
}

export function locate(doc: FlowDoc, id: string): Located | null {
  let found: Located | null = null;
  walk(doc, (l) => {
    if (!found && l.mod.id === id) found = l;
  });
  return found;
}

export function getList(doc: FlowDoc, ref: ContainerRef): RawModule[] | null {
  if (ref.owner === null) return doc.value.modules;
  const loc = locate(doc, ref.owner);
  if (!loc) return null;
  return childLists(loc.mod).find((c) => refKey(c.ref) === refKey(ref))?.list ?? null;
}

/** NAN-4661: the slot right after a step, in the same list; null when the step is gone. */
export function afterStep(doc: FlowDoc, id: string): DropAt | null {
  const loc = locate(doc, id);
  if (!loc) return null;
  const list = getList(doc, loc.ref);
  return { ref: loc.ref, before: list?.[loc.index + 1]?.id ?? null };
}

/** Depth of a container's modules (root = 1). */
export function refDepth(doc: FlowDoc, ref: ContainerRef): number {
  if (ref.owner === null) return 1;
  const loc = locate(doc, ref.owner);
  return loc ? loc.depth + 1 : 1;
}

export function allIds(doc: FlowDoc): Set<string> {
  const ids = new Set<string>();
  walk(doc, (l) => ids.add(l.mod.id));
  return ids;
}
export function moduleCount(doc: FlowDoc): number {
  return allIds(doc).size;
}
export function maxDepth(doc: FlowDoc): number {
  let d = 0;
  walk(doc, (l) => (d = Math.max(d, l.depth)));
  return d;
}
/** Levels a module occupies (1 for a leaf). */
export function height(m: RawModule): number {
  return 1 + Math.max(0, ...childLists(m).map((c) => Math.max(0, ...c.list.map(height))));
}
export function subtreeIds(m: RawModule): Set<string> {
  const ids = new Set<string>([m.id]);
  for (const c of childLists(m)) for (const k of c.list) subtreeIds(k).forEach((x) => ids.add(x));
  return ids;
}

/** Backend identifier rule: ASCII alphanumeric or `_`, first alphabetic. */
export function isIdentifier(s: string): boolean {
  return /^[A-Za-z][A-Za-z0-9_]*$/.test(s) && s.length <= 64;
}
export function freshId(taken: Set<string>, prefix = 's'): string {
  let n = 1;
  while (taken.has(`${prefix}${n}`)) n++;
  const id = `${prefix}${n}`;
  taken.add(id);
  return id;
}

// ── Operations (all return a new document) ──────────────────────────────

export function insertAt(doc: FlowDoc, mods: RawModule[], at: DropAt): FlowDoc {
  const next = structuredClone(doc);
  const list = getList(next, at.ref);
  if (!list) return doc;
  let i = at.before ? list.findIndex((m) => m.id === at.before) : list.length;
  if (i < 0) i = list.length;
  list.splice(i, 0, ...structuredClone(mods));
  return next;
}

export function removeModule(doc: FlowDoc, id: string): FlowDoc {
  const next = structuredClone(doc);
  const loc = locate(next, id);
  if (!loc) return doc;
  getList(next, loc.ref)!.splice(loc.index, 1);
  return next;
}

export function moveTo(doc: FlowDoc, id: string, at: DropAt): FlowDoc {
  if (at.before === id) return doc;
  const loc = locate(doc, id);
  if (!loc) return doc;
  if (at.ref.owner && subtreeIds(loc.mod).has(at.ref.owner)) return doc;
  const without = removeModule(doc, id);
  return insertAt(without, [loc.mod], at);
}

/** Move within the same container by one slot. */
export function nudge(doc: FlowDoc, id: string, dir: -1 | 1): FlowDoc {
  const loc = locate(doc, id);
  if (!loc) return doc;
  const list = getList(doc, loc.ref)!;
  const j = loc.index + dir;
  if (j < 0 || j >= list.length) return doc;
  const before = dir < 0 ? list[j].id : list[j + 1]?.id ?? null;
  return moveTo(doc, id, { ref: loc.ref, before });
}

function renameIds(m: RawModule, taken: Set<string>): RawModule {
  const copy = structuredClone(m);
  const visit = (x: RawModule) => {
    x.id = freshId(taken, x.id.replace(/\d+$/, '') || 's');
    for (const c of childLists(x)) c.list.forEach(visit);
  };
  visit(copy);
  return copy;
}

export function duplicateModule(doc: FlowDoc, id: string): { doc: FlowDoc; id: string | null } {
  const loc = locate(doc, id);
  if (!loc) return { doc, id: null };
  const list = getList(doc, loc.ref)!;
  const copy = renameIds(loc.mod, allIds(doc));
  return { doc: insertAt(doc, [copy], { ref: loc.ref, before: list[loc.index + 1]?.id ?? null }), id: copy.id };
}

export function updateModule(doc: FlowDoc, id: string, fn: (m: RawModule) => void): FlowDoc {
  const next = structuredClone(doc);
  const loc = locate(next, id);
  if (!loc) return doc;
  fn(loc.mod);
  return next;
}

// ── Drag rules ──────────────────────────────────────────────────────────

export type NewSpec =
  | { block: 'action'; pack: string; action: string }
  | { block: 'condition' | 'loop' | 'approval' | 'pass' | 'search' | 'email' | 'judge' };
export type DragItem = { kind: 'move'; id: string } | { kind: 'new'; spec: NewSpec; label: string } | { kind: 'trigger'; on: string; label: string };

/** Whether the flow already has its (single) condition. */
export function hasCondition(doc: FlowDoc): boolean {
  let found = false;
  walk(doc, (l) => (found ||= typeOf(l.mod) === 'branchone'));
  return found;
}

/** Whether a dragged item may land at `at`. Mirrors the mock's rules plus server limits. */
export function canDrop(doc: FlowDoc, drag: DragItem | null, at: DropAt): boolean {
  if (!drag || drag.kind === 'trigger') return false;
  if (!getList(doc, at.ref)) return false;
  const ownerChain: RawModule[] = [];
  if (at.ref.owner) {
    const l = locate(doc, at.ref.owner);
    if (!l) return false;
    ownerChain.push(...l.ancestors, l.mod);
  }
  const inLoop = ownerChain.some((m) => typeOf(m) === 'forloopflow');
  let mType: string;
  let h = 1;
  if (drag.kind === 'move') {
    if (at.before === drag.id) return false;
    const l = locate(doc, drag.id);
    if (!l) return false;
    if (ownerChain.some((m) => m.id === drag.id)) return false;
    mType = typeOf(l.mod);
    h = height(l.mod);
    if (mType === 'branchone' || mType === 'branchall') return false;
  } else {
    mType = drag.spec.block === 'loop' ? 'forloopflow' : drag.spec.block === 'condition' ? 'branchone' : drag.spec.block;
    if (moduleCount(doc) + 1 > LIMITS.modules) return false;
    // One condition per flow, top level only (the canvas renders the first
    // root `branchone` as the then/else split; root steps after it join).
    if (mType === 'branchone') return at.ref.owner === null && !hasCondition(doc);
  }
  if (mType === 'forloopflow' && inLoop) return false;
  return refDepth(doc, at.ref) + h - 1 <= LIMITS.depth;
}

// ── New modules ─────────────────────────────────────────────────────────

export interface Ctx {
  index: Map<string, IndexedAction>;
  connections: SoarConnection[];
}

export function connectionFor(ctx: Ctx, pack: string): string {
  return ctx.connections.find((c) => c.pack_name === pack)?.id ?? 'default';
}

export function makeModule(spec: NewSpec, ctx: Ctx, taken: Set<string>): RawModule {
  const id = freshId(taken);
  switch (spec.block) {
    case 'action': {
      const found = lookupAction(ctx.index, spec.pack, spec.action);
      const inputs: Json = {};
      for (const i of found?.action.inputs ?? []) if (i.required) inputs[i.name] = { type: 'expr', expr: '' };
      return {
        id,
        summary: found?.action.display_name ?? spec.action,
        value: { type: 'action', pack: spec.pack, action: spec.action, connection: connectionFor(ctx, spec.pack), input_transforms: inputs, approval: 'default' },
        timeout: { type: 'static', value: 120 },
      };
    }
    case 'loop':
      return { id, summary: 'For each', value: { type: 'forloopflow', iterator: { type: 'expr', expr: '' }, modules: [], skip_failures: false, parallel: false } };
    case 'approval':
      return {
        id,
        summary: 'Approve the next step?',
        value: { type: 'approval', prompt: 'Approve the next step?', options: ['approve', 'reject'] },
        suspend: { required_events: 1, timeout_secs: 3600, resume_form: 'none' },
      };
    case 'condition':
      return { id, summary: 'Condition', value: { type: 'branchone', branches: [{ expr: '', summary: 'then', modules: [] }], default: [] } };
    case 'search':
      return { id, summary: 'nPL search', value: { type: 'search', query: '', window: '24h', limit: 100 } };
    case 'judge':
      // NAN-4660: server defaults (judge.rs); question and evidence are filled in the inspector.
      return { id, summary: 'AI judge', value: { type: 'judge', question: '', labels: ['yes', 'no'], evidence: [], token_cap: JUDGE.tokenCap.default, cache_ttl: JUDGE.defaultTtl } };
    case 'email':
      return { id, summary: 'Email', value: { type: 'notify.email', to: '', subject: '', body: '', approval: 'default' } };
    default:
      return { id, summary: 'Pass-through', value: { type: 'identity' } };
  }
}

// ── Reading fields ──────────────────────────────────────────────────────

export type Transform = { type: 'static'; value: unknown } | { type: 'expr'; expr: string };
export function transform(v: unknown): Transform | null {
  const r = rec(v);
  if (!r) return null;
  if (r.type === 'expr') return { type: 'expr', expr: str(r.expr) };
  if (r.type === 'static') return { type: 'static', value: r.value };
  return null;
}
export function transformEmpty(t: Transform | null): boolean {
  if (!t) return true;
  if (t.type === 'expr') return t.expr.trim() === '';
  return t.value === '' || t.value === null || t.value === undefined;
}
export function staticNumber(v: unknown): number | null {
  const t = transform(v);
  return t?.type === 'static' && typeof t.value === 'number' ? t.value : null;
}
export function retryAttempts(m: RawModule): number {
  const r = rec(m.retry);
  const p = rec(r?.constant) ?? rec(r?.exponential);
  return typeof p?.attempts === 'number' ? p.attempts : 0;
}
export function suspendSecs(m: RawModule): number | null {
  const s = rec(m.suspend);
  return typeof s?.timeout_secs === 'number' ? s.timeout_secs : null;
}

export function actionOf(m: RawModule, index: Map<string, IndexedAction>): IndexedAction | undefined {
  return lookupAction(index, str(m.value.pack), str(m.value.action));
}
export function effectOf(m: RawModule, index: Map<string, IndexedAction>): Effect | null {
  const t = typeOf(m);
  if (t === 'action') return asEffect(actionOf(m, index)?.action.effect) ?? 'write';
  if (t === 'notify.email') return 'write';
  if (t === 'search' || t === 'judge') return 'read';
  return null;
}

// ── Conditions: `path = value`, `path in [a, b]`, or a value expression ──

export type CondOp = '=' | 'in' | 'expr';
export function parseCondition(expr: string): { op: CondOp; left: string; right: string } {
  const eq = /^\s*([A-Za-z_][\w.[\]-]*)\s*==?\s*(.+?)\s*$/.exec(expr);
  if (eq) return { op: '=', left: eq[1], right: eq[2] };
  const inn = /^\s*([A-Za-z_][\w.[\]-]*)\s+in\s+\[(.*)\]\s*$/.exec(expr);
  if (inn) return { op: 'in', left: inn[1], right: inn[2] };
  return { op: 'expr', left: expr, right: '' };
}
export function formatCondition(op: CondOp, left: string, right: string): string {
  if (op === 'expr') return left;
  if (op === 'in') return `${left} in [${right}]`;
  return `${left} = ${right}`;
}

// ── Local checks (port of the mock's stepErrors + server limits) ─────────

export function stepErrors(m: RawModule, ctx: Ctx): string[] {
  const e: string[] = [];
  const v = m.value;
  const t = typeOf(m);
  if (!isIdentifier(m.id)) e.push('Step id must start with a letter and use letters, digits or _');
  if (t === 'action') {
    const found = actionOf(m, ctx.index);
    if (!found) e.push(`${str(v.pack)}.${str(v.action)} is not in the installed catalog`);
    else {
      const map = rec(v.input_transforms) ?? {};
      for (const i of found.action.inputs) if (i.required && transformEmpty(transform(map[i.name]))) e.push(`${i.name} is required`);
      const fx = asEffect(found.action.effect);
      if (v.approval === 'auto' && (fx === 'destructive' || found.action.approval_forced)) e.push('This action cannot auto-approve');
    }
    if (!str(v.connection)) e.push('Connection is required');
  }
  if (t === 'forloopflow') {
    if (transformEmpty(transform(v.iterator))) e.push('Items expression is required');
    const p = staticNumber(v.parallelism);
    if (p !== null && p > LIMITS.parallelism) e.push(`Concurrency exceeds ${LIMITS.parallelism}`);
    if (!Array.isArray(v.modules) || v.modules.length === 0) e.push('Loop has no steps');
  }
  if (t === 'branchone') {
    const b = Array.isArray(v.branches) ? (v.branches as Json[]) : [];
    if (b.length === 0 || b.some((x) => !str(x.expr).trim())) e.push('Condition is required');
    else if (b.some((x) => /(=\s*""|in \[\])$/.test(str(x.expr).trim()))) e.push('Condition needs a value');
  }
  if (t === 'approval' && !str(v.prompt).trim()) e.push('Message to approver is required');
  if (t === 'search' && !str(v.query).trim()) e.push('Query is required');
  if (t === 'notify.email' && !str(v.to).trim()) e.push('Recipient is required');
  if (t === 'judge') e.push(...judgeErrors(v));
  const secs = staticNumber(m.timeout);
  if (secs !== null && secs > LIMITS.activeSecs) e.push('Timeout exceeds 15m step limit');
  const susp = suspendSecs(m);
  if (susp !== null && susp > LIMITS.wallSecs) e.push('Approval expiry exceeds the 24h run limit');
  return e;
}

export interface Finding {
  /** Module id, `trigger`, or null for the whole flow. */
  step: string | null;
  message: string;
}

export function localFindings(doc: FlowDoc, trigger: SoarFlowTrigger, ctx: Ctx): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  walk(doc, ({ mod }) => {
    if (seen.has(mod.id)) out.push({ step: mod.id, message: 'Duplicate step id' });
    seen.add(mod.id);
    for (const message of stepErrors(mod, ctx)) out.push({ step: mod.id, message });
  });
  if (doc.value.modules.length === 0) out.push({ step: null, message: 'A flow needs at least one step' });
  if (seen.size > LIMITS.modules) out.push({ step: null, message: `More than ${LIMITS.modules} modules` });
  if (maxDepth(doc) > LIMITS.depth) out.push({ step: null, message: `Nesting deeper than ${LIMITS.depth}` });
  if (trigger.on === 'schedule') {
    if (!trigger.cron?.trim()) out.push({ step: 'trigger', message: 'Schedule is required' });
    else {
      const every = everyMinutes(trigger.cron);
      if (every !== null && every < 5) out.push({ step: 'trigger', message: 'Schedule interval below 5 minutes' });
    }
  }
  return out;
}

/** Attribute a server validation message to the module ids it names. */
export function serverFindings(message: string, doc: FlowDoc): Finding[] {
  // NAN-4651: trigger-scope findings name their step exactly; don't also pin
  // them on steps whose ids happen to appear in the path (e.g. `user`).
  const named = /^module `([^`]+)`: /.exec(message)?.[1];
  if (named && allIds(doc).has(named)) return [{ step: named, message }];
  const ids = [...allIds(doc)].filter((id) => new RegExp(`(^|[^A-Za-z0-9_])${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^A-Za-z0-9_])`).test(message));
  return ids.length ? ids.map((step) => ({ step, message })) : [{ step: null, message }];
}

// ── Schedules: 7-field cron (sec min hour dom mon dow year) ─────────────

/** "every N minutes" for the simple cron forms the editor writes; null otherwise. */
export function everyMinutes(cron: string): number | null {
  const f = cron.trim().split(/\s+/);
  if (f.length < 6) return null;
  const [sec, min, hour, ...rest] = f;
  if (sec !== '0' || rest.slice(0, 3).some((x) => x !== '*')) return null;
  const m = /^\*\/(\d+)$/.exec(min);
  if (m && hour === '*') return Number(m[1]);
  const h = /^\*\/(\d+)$/.exec(hour);
  if (min === '0' && h) return Number(h[1]) * 60;
  if (min === '0' && hour === '*') return 60;
  return null;
}
export function cronEvery(minutes: number): string {
  if (minutes >= 60 && minutes % 60 === 0) return minutes === 60 ? '0 0 * * * * *' : `0 0 */${minutes / 60} * * * *`;
  return `0 */${Math.max(1, Math.round(minutes))} * * * * *`;
}
