// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4586 — the one field catalog for the flow editor's easy mode.
 *
 * Everything a flow can read lives in three namespaces (backend
 * the enterprise SOAR backend's soar/flow/compile.rs `Compiler::expression`):
 *   flow_input.*      the trigger event payload (or the inputs of a manual run)
 *   results.<step>.*  outputs of a step that ran earlier in the same container
 *   run.{id,case_id,tenant}
 *
 * Event payload shapes come from `nano_shared.enqueue_soar_source_event()`
 * in enterprise migration 9015160_soar_triage_verdict. The
 * pickers, the run-test form, the JSON key autocomplete and the expression
 * autocomplete all read this module, so they cannot drift from each other.
 */
import type { CaseWithDetails } from '@/lib/api/types';
import type { Finding, FlowDoc, Json, RawModule } from './flow-editor-model';
import { childLists, typeOf, walk } from './flow-editor-model';
import { evidencePath, judgeEvidence } from './judge-rules';
import type { IndexedAction } from './soar-model';
import { lookupAction } from './soar-model';

export type FieldType = 'string' | 'number' | 'boolean' | 'array' | 'object';
/** What a typed value must look like; drives free-text validation. */
export type ValueKind = 'text' | 'uuid' | 'ip' | 'number' | 'hash' | 'enum';

export interface FieldDef {
  /** Full scope path, e.g. `flow_input.alert.severity`. */
  path: string;
  /** Short human label, e.g. "Severity". */
  label: string;
  /** Picker group, e.g. "Alert". */
  group: string;
  type: FieldType;
  kind?: ValueKind;
  /** Known values: the value token becomes a dropdown. */
  values?: readonly string[];
  /** Sample value for the run-test form. */
  sample?: unknown;
  /** Present only on some events of a multi-event trigger (e.g. case transitions). */
  only?: string;
}

// ── Known values (mirror the DB check constraints / TS unions) ───────────

/** `alerts.kind` (NAN-1541). */
export const ALERT_KINDS = ['detection', 'metric_monitor', 'slo', 'synthetic', 'risk_notable'] as const;
export const ALERT_SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'] as const;
export const CASE_SEVERITIES = ALERT_SEVERITIES;
export const CASE_STATUSES = ['open', 'in_progress', 'pending', 'resolved', 'closed'] as const;
/** case_workflow_events kinds that enqueue a `case.transitioned` event. */
export const CASE_TRANSITIONS = ['closed', 'reopened', 'status_changed', 'pending_set', 'pending_cleared'] as const;
/** `ai_disposition` mapped by the trigger function. */
export const TRIAGE_VERDICTS = ['malicious', 'suspicious', 'benign', 'inconclusive'] as const;

// ── Event payloads ──────────────────────────────────────────────────────

export type EventKind = 'alert' | 'case.created' | 'case.transitioned' | 'case.triage_verdict' | 'schedule' | 'manual';

const SAMPLE_UUID = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

const f = (path: string, label: string, group: string, type: FieldType, extra: Partial<FieldDef> = {}): FieldDef => ({
  path: `flow_input.${path}`,
  label,
  group,
  type,
  ...extra,
});

const ALERT_CORE: FieldDef[] = [
  f('alert.id', 'Alert ID', 'Alert', 'string', { kind: 'uuid', sample: SAMPLE_UUID(1) }),
  f('alert.rule_id', 'Rule ID', 'Alert', 'string', { kind: 'uuid', sample: SAMPLE_UUID(2) }),
  f('alert.severity', 'Severity', 'Alert', 'string', { kind: 'enum', values: ALERT_SEVERITIES, sample: 'high' }),
  f('alert.tags', 'Rule tags', 'Alert', 'array', { sample: ['attack.t1059'] }),
];

/**
 * NAN-4585 (#7935): context `nano_shared.soar_alert_context()` adds to the
 * alert payload: rule name (or null), display title (rule name, else
 * "<Kind> alert"), kind, created_at (UTC RFC3339) and the main entities from
 * the alert's matched events. Entity keys are always present (string or
 * null) unless dropped for the 16 KiB payload cap; `is` against a null
 * entity is simply false.
 */
export const ALERT_CONTEXT_FIELDS: FieldDef[] = [
  f('alert.rule_name', 'Rule name', 'Alert', 'string', { sample: 'Suspicious PowerShell' }),
  f('alert.title', 'Title', 'Alert', 'string', { sample: 'Suspicious PowerShell' }),
  f('alert.kind', 'Kind', 'Alert', 'string', { kind: 'enum', values: ALERT_KINDS, sample: 'detection' }),
  f('alert.created_at', 'Created at', 'Alert', 'string', { sample: '2026-10-26T12:00:00.000000Z' }),
  f('alert.entities.host', 'Host', 'Alert', 'string', { sample: 'FIN-LT-0388' }),
  f('alert.entities.user', 'User', 'Alert', 'string', { sample: 'jdoe' }),
  f('alert.entities.src_ip', 'Source IP', 'Alert', 'string', { kind: 'ip', sample: '10.20.4.17' }),
  f('alert.entities.dest_ip', 'Destination IP', 'Alert', 'string', { kind: 'ip', sample: '203.0.113.50' }),
  f('alert.entities.process', 'Process', 'Alert', 'string', { sample: 'powershell.exe' }),
  f('alert.entities.command_line', 'Command line', 'Alert', 'string', { sample: 'powershell.exe -enc SQBFAFgA' }),
  f('alert.entities.hash', 'File hash', 'Alert', 'string', { kind: 'hash', sample: 'd41d8cd98f00b204e9800998ecf8427e' }),
  f('alert.entities.domain', 'Domain', 'Alert', 'string', { sample: 'example.com' }),
];

const CASE_CORE: FieldDef[] = [
  f('case.id', 'Case ID', 'Case', 'string', { kind: 'uuid', sample: SAMPLE_UUID(3) }),
  f('case.status', 'Status', 'Case', 'string', { kind: 'enum', values: CASE_STATUSES, sample: 'open' }),
  f('case.severity', 'Severity', 'Case', 'string', { kind: 'enum', values: CASE_SEVERITIES, sample: 'high' }),
];

const CASE_TRANSITION: FieldDef[] = [
  f('case.id', 'Case ID', 'Case', 'string', { kind: 'uuid', sample: SAMPLE_UUID(3) }),
  f('case.status', 'New status', 'Case', 'string', { kind: 'enum', values: CASE_STATUSES, sample: 'closed' }),
  f('case.previous_status', 'Previous status', 'Case', 'string', { kind: 'enum', values: CASE_STATUSES, sample: 'in_progress' }),
  f('case.event', 'Change', 'Case', 'string', { kind: 'enum', values: CASE_TRANSITIONS, sample: 'closed' }),
];

const TRIAGE: FieldDef[] = [
  ...CASE_CORE,
  f('verdict', 'Verdict', 'Triage verdict', 'string', { kind: 'enum', values: TRIAGE_VERDICTS, sample: 'malicious' }),
  f('confidence', 'Confidence (0–1)', 'Triage verdict', 'number', { kind: 'number', sample: 0.92 }),
  f('alert_ids', 'Alert IDs', 'Triage verdict', 'array', { sample: [SAMPLE_UUID(1)] }),
  f('top_entities', 'Top entities', 'Triage verdict', 'array', { sample: [{ type: 'host', value: 'FIN-LT-0388' }] }),
];

export const EVENT_FIELDS: Record<EventKind, FieldDef[]> = {
  alert: [...ALERT_CORE, ...ALERT_CONTEXT_FIELDS],
  'case.created': CASE_CORE,
  'case.transitioned': CASE_TRANSITION,
  'case.triage_verdict': TRIAGE,
  schedule: [],
  manual: [],
};

export const EVENT_LABEL: Record<EventKind, string> = {
  alert: 'Alert committed',
  'case.created': 'Case created',
  'case.transitioned': 'Case status changed',
  'case.triage_verdict': 'Case triage verdict',
  schedule: 'Schedule',
  manual: 'Manual',
};

/** Event kinds a stored trigger `on` value can receive. */
export function triggerEvents(on: string): EventKind[] {
  if (on === 'case') return ['case.created', 'case.transitioned'];
  if (on === 'alert' || on === 'case.triage_verdict' || on === 'schedule') return [on];
  return ['manual'];
}

/** `flow_input` fields for a trigger, merged across its events. */
export function inputFields(on: string): FieldDef[] {
  const events = triggerEvents(on);
  const byPath = new Map<string, FieldDef & { seen: Set<EventKind> }>();
  for (const ev of events) {
    for (const d of EVENT_FIELDS[ev]) {
      const cur = byPath.get(d.path);
      if (cur) cur.seen.add(ev);
      else byPath.set(d.path, { ...d, seen: new Set([ev]) });
    }
  }
  return [...byPath.values()].map(({ seen, ...d }) => (events.length > 1 && seen.size < events.length ? { ...d, only: [...seen].map((e) => EVENT_LABEL[e]).join(', ') } : d));
}

// ── Step outputs and run ────────────────────────────────────────────────

export const RUN_FIELDS: FieldDef[] = [
  { path: 'run.id', label: 'Run ID', group: 'Run', type: 'string', kind: 'uuid' },
  { path: 'run.case_id', label: 'Case ID', group: 'Run', type: 'string', kind: 'uuid' },
  { path: 'run.tenant', label: 'Tenant', group: 'Run', type: 'string' },
];

export const LOOP_FIELDS: FieldDef[] = [
  { path: 'flow_input.iter.value', label: 'Current item', group: 'Loop item', type: 'string' },
  { path: 'flow_input.iter.index', label: 'Item number (from 0)', group: 'Loop item', type: 'number', kind: 'number' },
];

/** Optional declared outputs on a catalog action (not on every server build). */
function declaredOutputs(found: IndexedAction | undefined): Array<[string, FieldType]> {
  const raw = (found?.action as unknown as { outputs?: unknown; output_types?: unknown } | undefined) ?? {};
  const typed = raw.output_types && typeof raw.output_types === 'object' ? (raw.output_types as Record<string, unknown>) : null;
  const names = Array.isArray(raw.outputs) ? raw.outputs.filter((x): x is string => typeof x === 'string') : raw.outputs && typeof raw.outputs === 'object' ? Object.keys(raw.outputs) : [];
  const asType = (t: unknown): FieldType => (t === 'number' || t === 'integer' ? 'number' : t === 'boolean' ? 'boolean' : t === 'array' ? 'array' : t === 'object' ? 'object' : 'string');
  const all = new Set([...names, ...(typed ? Object.keys(typed) : [])]);
  return [...all].sort().map((n) => {
    const t = typed?.[n];
    return [n, asType(typeof t === 'string' ? t : (t as { type?: unknown } | undefined)?.type)];
  });
}

export function stepOutputFields(m: RawModule, index: Map<string, IndexedAction>): FieldDef[] {
  const t = typeOf(m);
  const group = `Step ${m.id}${m.summary ? ` · ${m.summary}` : ''}`;
  const r = (sub: string, label: string, type: FieldType, extra: Partial<FieldDef> = {}): FieldDef => ({ path: `results.${m.id}${sub ? `.${sub}` : ''}`, label, group, type, ...extra });
  if (t === 'search') {
    return [
      r('summary.count', 'Rows found', 'number', { kind: 'number' }),
      r('summary.total_count', 'Total matches', 'number', { kind: 'number' }),
      r('summary.total_count_exact', 'Total is exact', 'boolean'),
      r('summary.distinct_values', 'Distinct values by field', 'object'),
      r('rows', 'Rows', 'array'),
      r('truncated', 'Output was cut', 'boolean'),
    ];
  }
  if (t === 'judge') {
    const labels = Array.isArray(m.value.labels) ? (m.value.labels as unknown[]).filter((x): x is string => typeof x === 'string') : [];
    return [
      r('verdict', 'Verdict', 'string', labels.length ? { kind: 'enum', values: [...labels, 'unknown'] } : {}),
      r('confidence', 'Confidence', 'number', { kind: 'number' }),
      r('why', 'Reason', 'string'),
      r('tokens', 'Tokens used', 'number', { kind: 'number' }),
      r('cached', 'From cache', 'boolean'),
    ];
  }
  if (t === 'action') {
    const found = lookupAction(index, String(m.value.pack ?? ''), String(m.value.action ?? ''));
    const outs = declaredOutputs(found);
    if (outs.length) return outs.map(([n, type]) => r(n, n, type, type === 'number' ? { kind: 'number' } : {}));
    return [r('', 'Whole output', 'object')];
  }
  if (t === 'approval') return [r('', 'Decision', 'object')];
  return [r('', 'Whole output', 'object')];
}

/** Steps whose results are visible to `targetId`, plus how many loops enclose it (compile.rs `modules`). */
export function visibleScope(doc: FlowDoc, targetId: string): { steps: RawModule[]; loops: number } | null {
  const visit = (list: RawModule[], visible: RawModule[], loops: number): { steps: RawModule[]; loops: number } | null => {
    const vis = [...visible];
    for (const m of list) {
      if (m.id === targetId) return { steps: vis, loops };
      const inner = loops + (typeOf(m) === 'forloopflow' ? 1 : 0);
      for (const c of childLists(structuredClone(m))) {
        const hit = visit(c.list, vis, inner);
        if (hit) return hit;
      }
      vis.push(m);
    }
    return null;
  };
  return visit(doc.value.modules, [], 0);
}

/** What the server's search validation needs about where a step sits. */
export interface SearchStepScope {
  trigger?: 'manual' | 'alert' | 'case' | 'case.triage_verdict' | 'schedule';
  priorSteps: string[];
  inLoop: boolean;
}
const TRIGGER_KINDS = new Set(['manual', 'alert', 'case', 'case.triage_verdict', 'schedule']);
/** A stored trigger `on` the server's TriggerKind accepts; undefined otherwise. */
export function triggerKind(on: string): SearchStepScope['trigger'] {
  return TRIGGER_KINDS.has(on) ? (on as SearchStepScope['trigger']) : undefined;
}
export function searchStepScope(doc: FlowDoc, on: string, stepId: string): SearchStepScope {
  const scope = visibleScope(doc, stepId);
  return {
    trigger: triggerKind(on),
    priorSteps: (scope?.steps ?? []).map((m) => m.id),
    inLoop: (scope?.loops ?? 0) > 0,
  };
}

/**
 * `flow_input` paths a flow references that the trigger catalog does not
 * know (manual-run inputs). The step being edited is skipped so a half-typed
 * expression never suggests itself.
 */
export function referencedInputPaths(doc: FlowDoc, known: Set<string>, skipId: string | null = null): string[] {
  const out = new Set<string>();
  const texts: string[] = [];
  walk(doc, ({ mod }) => {
    if (mod.id === skipId) return;
    const { modules: _m, default: _d, branches, ...own } = mod.value;
    void _m; void _d;
    texts.push(JSON.stringify(own), JSON.stringify(Array.isArray(branches) ? (branches as Json[]).map((b) => b.expr) : []));
  });
  for (const m of texts.join('\n').matchAll(/flow_input\.[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*/g)) {
    const p = m[0];
    if (!p.startsWith('flow_input.iter') && !known.has(p)) out.add(p);
  }
  return [...out].sort();
}

/** Every path an expression at `stepId` may read, in picker order. */
export function scopeFields(doc: FlowDoc, on: string, stepId: string | null, index: Map<string, IndexedAction>, opts: { inLoopBody?: boolean } = {}): FieldDef[] {
  const input = inputFields(on);
  const known = new Set(input.map((x) => x.path));
  // NAN-4651: only alert-triggered runs carry an alert; never offer a stray
  // flow_input.alert.* path under another trigger (the server refuses it).
  const custom = referencedInputPaths(doc, known, stepId)
    .filter((p) => on === 'alert' || !p.startsWith('flow_input.alert.'))
    .map((p): FieldDef => ({ path: p, label: p.slice('flow_input.'.length), group: 'Flow input', type: 'string' }));
  const scope = stepId ? visibleScope(doc, stepId) : { steps: doc.value.modules, loops: 0 };
  const loops = (scope?.loops ?? 0) + (opts.inLoopBody ? 1 : 0);
  return [
    ...input,
    ...custom,
    ...(loops > 0 ? LOOP_FIELDS : []),
    ...(scope?.steps ?? []).flatMap((m) => stepOutputFields(m, index)),
    ...RUN_FIELDS,
  ];
}

// ── Judge evidence (NAN-4660) ───────────────────────────────────────────

/** Only alert-triggered runs carry an alert (NAN-4651); every other trigger refuses alert.* reads. */
const alertOk = (on: string, path: string) => on === 'alert' || !path.startsWith('flow_input.alert.');

/** Fields a judge at `stepId` may cite as evidence: the visible scope minus alert.* outside alert triggers. */
export function judgeEvidenceFields(doc: FlowDoc, on: string, stepId: string, index: Map<string, IndexedAction>): FieldDef[] {
  return scopeFields(doc, on, stepId, index).filter((d) => alertOk(on, d.path));
}

/** Why one evidence reference cannot be read at `stepId`, or null (scope only; shape is judge-rules). */
export function evidenceScopeProblem(doc: FlowDoc, on: string, stepId: string, reference: string): string | null {
  const path = evidencePath(reference);
  if (!path) return null;
  if (!alertOk(on, path)) return `a ${on} trigger has no alert; use an alert trigger or a run input`;
  const scope = visibleScope(doc, stepId);
  if (path.startsWith('results.')) {
    const id = path.split('.')[1];
    if (!scope?.steps.some((m) => m.id === id)) return `step ${id} has not run before this step`;
  }
  if (path.startsWith('flow_input.iter.') && !(scope && scope.loops > 0)) return 'the loop item exists only inside a loop';
  return null;
}

/** Scope findings for every judge step's evidence (the trigger-dependent half of the judge checks). */
export function judgeScopeFindings(doc: FlowDoc, on: string): Finding[] {
  const out: Finding[] = [];
  walk(doc, ({ mod }) => {
    if (typeOf(mod) !== 'judge') return;
    for (const r of judgeEvidence(mod.value)) {
      const p = evidenceScopeProblem(doc, on, mod.id, r);
      if (p) out.push({ step: mod.id, message: `Evidence ${r}: ${p}` });
    }
  });
  return out;
}

export function fieldFor(path: string, fields: FieldDef[]): FieldDef | undefined {
  return fields.find((x) => x.path === path);
}

/** "Alert → Severity", or the raw path for anything unknown. */
export function fieldLabel(path: string, fields: FieldDef[]): string {
  const d = fieldFor(path, fields);
  return d ? `${d.group.replace(/ · .*$/, '')} → ${d.label}` : path;
}

export const isPath = (s: string) => /^(flow_input|results|run)(\.[A-Za-z_][\w]*)+$/.test(s);

// ── Free-text validation ────────────────────────────────────────────────

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
/** One address. Conditions compare exactly (case-insensitive), so CIDR ranges never match. */
function isIp(addr: string): boolean {
  if (IPV4.test(addr)) return true;
  return addr.includes(':') && /^[0-9a-f:.]+$/i.test(addr) && (addr.match(/::/g) ?? []).length <= 1 && addr.split(':').length <= 8;
}

/** Infer the kind for fields without an explicit one (custom paths, step outputs). */
export function kindOf(path: string, d?: FieldDef): ValueKind {
  if (d?.kind) return d.kind;
  if (d?.type === 'number') return 'number';
  const tail = path.split('.').pop() ?? '';
  if (/(^|_)ip$|^ip_|_addr$/.test(tail)) return 'ip';
  if (/(^|_)(hash|md5|sha1|sha256)$/.test(tail)) return 'hash';
  return 'text';
}

/** A message when `v` is not a valid value of `kind`; null when fine. */
export function checkValue(kind: ValueKind, v: string, values?: readonly string[]): string | null {
  const s = v.trim();
  if (!s) return null;
  if (/["\]]/.test(s)) return 'Values cannot contain " or ].';
  switch (kind) {
    case 'ip':
      return isIp(s) ? null : 'Enter one IP address, e.g. 10.0.0.1. Ranges are not supported.';
    case 'number':
      return /^-?\d+(\.\d+)?$/.test(s) ? null : 'Enter a number.';
    case 'hash':
      return /^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i.test(s) ? null : 'Enter an MD5, SHA-1 or SHA-256 hash.';
    case 'uuid':
      return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s) ? null : 'Enter an ID like 3f2b…-…';
    case 'enum':
      return !values || values.includes(s) ? null : `Expected one of ${values.join(', ')}.`;
    default:
      return null;
  }
}

// ── Branch conditions: the easy-mode sentence ───────────────────────────

/** `is` writes `path = v`, `one_of` writes `path in [a, b]`, `true` writes the bare path. */
export type EasyOp = 'is' | 'one_of' | 'true';
export interface EasyCondition {
  path: string;
  op: EasyOp;
  /** Display values (quotes removed). */
  values: string[];
}

const unquote = (t: string) => (/^"[^"]*"$/.test(t) ? t.slice(1, -1) : t);
/**
 * Quote a literal only for leading/trailing whitespace or empty. Commas are
 * never written (conditionValueProblem refuses them), so a stored value with
 * one stays advanced.
 */
export function literal(v: string): string {
  return /^\s|\s$|^$/.test(v) ? `"${v}"` : v;
}

/** A condition value the sentence can write: typed check plus no commas. */
export function conditionValueProblem(kind: ValueKind, v: string, values?: readonly string[]): string | null {
  if (v.includes(',')) return 'Commas are not allowed in a value. Use "is one of" for several values.';
  return checkValue(kind, v, values);
}

export function formatEasyCondition(c: EasyCondition): string {
  if (!c.path) return '';
  if (c.op === 'true') return c.path;
  if (c.op === 'one_of') return `${c.path} in [${c.values.map(literal).join(', ')}]`;
  return `${c.path} = ${literal(c.values[0] ?? '')}`;
}

/**
 * The easy form of a stored condition, or null when the sentence cannot show
 * it exactly. Exactness is checked by re-formatting: easy mode only ever
 * rewrites a condition the user changes in it, and only from a form that
 * round-trips byte for byte.
 */
export function parseEasyCondition(expr: string): EasyCondition | null {
  if (expr === '') return { path: '', op: 'is', values: [] };
  let c: EasyCondition | null = null;
  const inn = /^([A-Za-z_][\w.]*) in \[(.*)\]$/.exec(expr);
  const eq = /^([A-Za-z_][\w.]*) = (.+)$/.exec(expr);
  if (inn) c = { path: inn[1], op: 'one_of', values: inn[2] === '' ? [] : inn[2].split(', ').map(unquote) };
  else if (eq) c = { path: eq[1], op: 'is', values: [unquote(eq[2])] };
  else if (/^[A-Za-z_][\w.]*$/.test(expr)) c = { path: expr, op: 'true', values: [] };
  if (!c || !isPath(c.path)) return null;
  if (c.values.some((v) => v.includes('"') || v.includes(','))) return null;
  return formatEasyCondition(c) === expr ? c : null;
}

export const EASY_OP_LABEL: Record<EasyOp, string> = { is: 'is', one_of: 'is one of', true: 'is true' };

export interface ConditionParts {
  path: string;
  /** Friendly "Alert → Severity" when the path resolves in the catalog; null for unknown paths. */
  label: string | null;
  op: string;
  values: string[];
}

/** The sentence pieces for the canvas label; null when not expressible. */
export function conditionParts(expr: string, fields: FieldDef[]): ConditionParts | null {
  const c = parseEasyCondition(expr);
  if (!c || !c.path) return null;
  return { path: c.path, label: fieldFor(c.path, fields) ? fieldLabel(c.path, fields) : null, op: EASY_OP_LABEL[c.op], values: c.values };
}

/** Plain-language form of a condition; null when not expressible. */
export function describeCondition(expr: string, fields: FieldDef[]): string | null {
  const p = conditionParts(expr, fields);
  if (!p) return null;
  return `When ${p.label ?? p.path} ${p.op}${p.values.length ? ` ${p.values.join(', ')}` : ''}`;
}

// ── Expression autocomplete ─────────────────────────────────────────────

export interface Helper {
  name: string;
  signature: string;
  doc: string;
}
/** Closed helper set accepted by flow expressions (nano-connector template). */
export const HELPERS: Helper[] = [
  { name: 'coalesce', signature: 'coalesce a b …', doc: 'First value that is present (2–16 arguments)' },
  { name: 'first', signature: 'first list', doc: 'First item of a list' },
  { name: 'join', signature: 'join list ","', doc: 'Join a list with a separator' },
  { name: 'lower', signature: 'lower text', doc: 'Lowercase text' },
];

export interface Suggestion {
  /** Inserted text. */
  apply: string;
  /** Shown text. */
  label: string;
  detail: string;
  kind: 'field' | 'helper';
}
export interface Completion {
  from: number;
  to: number;
  options: Suggestion[];
}

/**
 * Suggestions for the word at `pos` in a flow expression: catalog paths by
 * prefix first, then by label/path substring, plus helpers for bare words.
 * Returns null inside a string literal.
 */
export function completeExpression(text: string, pos: number, fields: FieldDef[], max = 40): Completion | null {
  const before = text.slice(0, pos);
  if (((before.match(/(?<!\\)"/g) ?? []).length & 1) === 1) return null;
  const word = /[A-Za-z_][\w.]*$/.exec(before)?.[0] ?? '';
  const tail = /^[\w.]*/.exec(text.slice(pos))?.[0] ?? '';
  const q = word.toLowerCase();
  const prefix: Suggestion[] = [];
  const loose: Suggestion[] = [];
  for (const d of fields) {
    const s: Suggestion = { apply: d.path, label: d.path, detail: `${d.group.replace(/ · .*$/, '')} → ${d.label}`, kind: 'field' };
    if (d.path.toLowerCase().startsWith(q)) prefix.push(s);
    else if (q.length >= 2 && (d.path.toLowerCase().includes(q) || d.label.toLowerCase().includes(q))) loose.push(s);
  }
  const helpers: Suggestion[] = q.includes('.')
    ? []
    : HELPERS.filter((h) => h.name.startsWith(q)).map((h) => ({ apply: `${h.name} `, label: h.name, detail: `${h.signature} — ${h.doc}`, kind: 'helper' }));
  const options = [...prefix, ...helpers, ...loose].slice(0, max);
  return { from: pos - word.length, to: pos + tail.length, options };
}

// ── Run-test inputs ─────────────────────────────────────────────────────

function setPath(obj: Json, path: string, value: unknown) {
  const parts = path.split('.');
  let cur: Json = obj;
  for (const p of parts.slice(0, -1)) {
    if (!cur[p] || typeof cur[p] !== 'object' || Array.isArray(cur[p])) cur[p] = {};
    cur = cur[p] as Json;
  }
  cur[parts[parts.length - 1]] = value;
}
export function getPath(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const p of path.split('.')) {
    if (!cur || typeof cur !== 'object' || Array.isArray(cur)) return undefined;
    cur = (cur as Json)[p];
  }
  return cur;
}
export const inputKey = (path: string) => path.replace(/^flow_input\./, '');

/** Inputs object from `{ inputKey: value }` pairs. */
export function buildInputs(values: Array<[string, unknown]>): Json {
  const out: Json = {};
  for (const [k, v] of values) setPath(out, k, v);
  return out;
}

/** The event's sample payload, as the trigger function would send it. */
export function sampleInputs(ev: EventKind): Json {
  return buildInputs(EVENT_FIELDS[ev].map((d) => [inputKey(d.path), structuredClone(d.sample ?? '')]));
}

const VERDICT_OF: Record<string, (typeof TRIAGE_VERDICTS)[number]> = {
  true_positive: 'malicious',
  needs_investigation: 'suspicious',
  false_positive: 'benign',
  benign: 'benign',
};

/** Payload for a real case, shaped per event kind. */
export function inputsFromCase(c: Pick<CaseWithDetails, 'id' | 'status' | 'severity'> & Partial<CaseWithDetails>, ev: EventKind): Json {
  if (ev === 'case.transitioned') return { case: { id: c.id, status: c.status, previous_status: c.status === 'closed' ? 'in_progress' : 'open', event: c.status === 'closed' ? 'closed' : 'status_changed' } };
  const base = { case: { id: c.id, status: c.status, severity: c.severity } };
  if (ev !== 'case.triage_verdict') return base;
  return { ...base, verdict: VERDICT_OF[c.ai_disposition ?? ''] ?? 'inconclusive', confidence: c.ai_confidence ?? null, alert_ids: [], top_entities: [] };
}

// ── JSON editing support (advanced run-test tab) ────────────────────────

export interface Issue {
  message: string;
  /** Character offset of the offending key or value; 0 when unknown. */
  at: number;
  severity: 'error' | 'warning';
}

function offsetOfKey(text: string, key: string): number {
  const i = text.indexOf(`"${key}"`);
  return i < 0 ? 0 : i;
}

const typeOfValue = (v: unknown): FieldType => (Array.isArray(v) ? 'array' : v === null ? 'object' : (typeof v as FieldType));

/** Parse + check inputs JSON against the trigger catalog. */
export function checkInputsJson(text: string, on: string): { value: Json | null; issues: Issue[] } {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch (e) {
    const m = /position (\d+)/.exec(String((e as Error).message));
    return { value: null, issues: [{ message: `Not valid JSON: ${(e as Error).message}`, at: m ? Number(m[1]) : 0, severity: 'error' }] };
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return { value: null, issues: [{ message: 'Inputs must be a JSON object { … }.', at: 0, severity: 'error' }] };
  const issues: Issue[] = [];
  const fields = inputFields(on);
  if (fields.length) {
    const roots = new Set(fields.map((d) => inputKey(d.path).split('.')[0]));
    for (const k of Object.keys(v)) if (!roots.has(k)) issues.push({ message: `"${k}" is not part of the ${triggerEvents(on).map((e) => EVENT_LABEL[e]).join(' / ')} event.`, at: offsetOfKey(text, k), severity: 'warning' });
  }
  for (const d of fields) {
    const got = getPath(v, inputKey(d.path));
    if (got === undefined || got === null) continue;
    const key = inputKey(d.path).split('.').pop()!;
    const t = typeOfValue(got);
    if (t !== d.type) issues.push({ message: `${inputKey(d.path)} should be ${d.type === 'array' ? 'a list' : `a ${d.type}`}.`, at: offsetOfKey(text, key), severity: 'warning' });
    else if (d.values && typeof got === 'string' && !d.values.includes(got)) issues.push({ message: `${inputKey(d.path)} should be one of ${d.values.join(', ')}.`, at: offsetOfKey(text, key), severity: 'warning' });
  }
  return { value: v as Json, issues };
}

/**
 * Object-key context at `pos` in a JSON document: the key path of the
 * enclosing object and the partial key being typed. Null outside a key slot.
 */
export function jsonKeyContext(text: string, pos: number): { path: string[]; partial: string; from: number; quoted: boolean } | null {
  type Frame = { obj: boolean; key: string | null; expectKey: boolean };
  const stack: Frame[] = [];
  let i = 0;
  while (i < pos) {
    const ch = text[i];
    if (ch === '"') {
      const start = i + 1;
      let j = start;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (j >= pos) {
        // Cursor inside this string.
        if (top?.obj && top.expectKey) return { path: stack.slice(0, -1).map((fr) => fr.key ?? ''), partial: text.slice(start, pos), from: start, quoted: true };
        return null;
      }
      if (top?.obj && top.expectKey) {
        top.key = text.slice(start, j);
        top.expectKey = false;
      }
      i = j + 1;
      continue;
    }
    if (ch === '{') stack.push({ obj: true, key: null, expectKey: true });
    else if (ch === '[') stack.push({ obj: false, key: null, expectKey: false });
    else if (ch === '}' || ch === ']') stack.pop();
    else if (ch === ',') {
      const top = stack[stack.length - 1];
      if (top?.obj) top.expectKey = true;
    }
    i++;
  }
  const top = stack[stack.length - 1];
  if (!top?.obj || !top.expectKey) return null;
  const word = /[A-Za-z_]\w*$/.exec(text.slice(0, pos))?.[0] ?? '';
  return { path: stack.slice(0, -1).map((fr) => fr.key ?? ''), partial: word, from: pos - word.length, quoted: false };
}

/** Catalog keys valid at a JSON key slot (path is the enclosing objects' keys). */
export function jsonKeyOptions(on: string, path: string[]): Array<{ key: string; detail: string }> {
  if (path.some((p) => !p)) return [];
  const prefix = path.length ? `${path.join('.')}.` : '';
  const seen = new Map<string, { key: string; detail: string }>();
  for (const d of inputFields(on)) {
    const k = inputKey(d.path);
    if (!k.startsWith(prefix)) continue;
    const rest = k.slice(prefix.length).split('.');
    const key = rest[0];
    if (seen.has(key)) continue;
    seen.set(key, rest.length > 1 ? { key, detail: 'object' } : { key, detail: d.values ? d.values.join(' | ') : d.type });
  }
  return [...seen.values()];
}

// ── Search step bindings ────────────────────────────────────────────────

/** Backend marker (flow/search.rs `MARKER`); authored queries may not contain it. */
export const SEARCH_MARKER = 'NANOSOARBOUNDLITERAL';

/**
 * Mirror of `PlannedSearch::compile`'s template pass: each `{{path}}` becomes
 * the quoted marker literal `"NANOSOARBOUNDLITERAL<i>"`, `alert.` / `steps.`
 * aliases are expanded, and malformed bindings fail with the same rules.
 */
export function searchSkeleton(query: string): { skeleton: string; paths: string[] } | { error: string } {
  if (query.includes(SEARCH_MARKER)) return { error: `The query may not contain ${SEARCH_MARKER}.` };
  let rest = query;
  let skeleton = '';
  const paths: string[] = [];
  for (let start = rest.indexOf('{{'); start >= 0; start = rest.indexOf('{{')) {
    if (paths.length >= 64) return { error: 'At most 64 inserted fields.' };
    const tail = rest.slice(start + 2);
    const close = tail.indexOf('}}');
    if (close < 0) return { error: 'An inserted field is missing its closing }}.' };
    const ref = tail.slice(0, close).trim();
    const path = ref.startsWith('alert.') ? `flow_input.${ref}` : ref.startsWith('steps.') ? `results.${ref.slice(6)}` : ref;
    if (path.split('.').some((seg) => !/^[A-Za-z0-9_]{1,64}$/.test(seg))) return { error: `"${ref}" is not a field path.` };
    skeleton += `${rest.slice(0, start)}"${SEARCH_MARKER}${paths.length}"`;
    paths.push(path);
    rest = tail.slice(close + 2);
  }
  if (rest.includes('}}')) return { error: 'Unmatched }} in the query.' };
  return { skeleton: skeleton + rest, paths };
}

/**
 * Outer `earliest=` / `latest=` modifiers (nanosiem-core
 * `has_outer_time_modifiers`): quote- and escape-aware, word-boundary only,
 * ignoring `[...]` subsearches. A search step's window is fixed by the step.
 */
export function outerTimeModifiers(query: string): string[] {
  const text = query.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|\n)\s*\/\/[^\n]*/g, '$1');
  const out: string[] = [];
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'") {
      for (i++; i < text.length && text[i] !== c; i++) if (text[i] === '\\') i++;
      continue;
    }
    if (c === '\\') { i++; continue; }
    if (c === '[') { depth++; continue; }
    if (c === ']') { depth = Math.max(0, depth - 1); continue; }
    const prev = i > 0 ? text[i - 1] : '';
    if (/[\w.]/.test(prev)) continue;
    const m = /^(earliest|latest)=[^\s|\]]*/i.exec(text.slice(i));
    if (m && depth === 0) { out.push(m[0]); i += m[0].length - 1; }
  }
  return out;
}

export function insertBinding(query: string, at: number, path: string): { text: string; caret: number } {
  const token = `{{${path}}}`;
  const pos = Math.max(0, Math.min(at, query.length));
  const pad = pos > 0 && !/[\s=(,]$/.test(query.slice(0, pos)) ? ' ' : '';
  const text = query.slice(0, pos) + pad + token + query.slice(pos);
  return { text, caret: pos + pad.length + token.length };
}

export const BINDING = /\{\{\s*([^}]*?)\s*\}\}/g;

export type BindingPart = { text: string } | { path: string; label: string | null; raw: string };

/** Split a query into literal text and `{{path}}` bindings with friendly labels. */
export function bindingParts(query: string, fields: FieldDef[]): BindingPart[] {
  const out: BindingPart[] = [];
  let last = 0;
  for (const m of query.matchAll(BINDING)) {
    if (m.index > last) out.push({ text: query.slice(last, m.index) });
    out.push({ path: m[1], label: fieldFor(m[1], fields) ? fieldLabel(m[1], fields) : null, raw: m[0] });
    last = m.index + m[0].length;
  }
  if (last < query.length) out.push({ text: query.slice(last) });
  return out;
}
