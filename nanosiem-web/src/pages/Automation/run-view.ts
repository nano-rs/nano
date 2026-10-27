// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — view models for the Runs page, trace and approvals, mapping the
 * real run / step / approval DTOs onto the design mock's vocabulary
 * (verb → target · vendor, origin, outcome, spans).
 */
import type { SoarApproval, SoarCatalogAction, SoarFlow, SoarRun, SoarRunDetail, SoarStepResult } from '@/lib/api/soar';
import {
  asEffect,
  formatDuration,
  inputTargets,
  lookupAction,
  runDuration,
  runOutcome,
  shortId,
  verbOf,
  type Effect,
  type EntityKind,
  type IndexedAction,
  type Outcome,
} from './soar-model';
import type { OriginKind, OutcomeKey } from './soar-kit';
import { outcomeKey } from './soar-kit';

export type RunSource = 'user' | 'trigger' | 'pivt';

export function runSource(run: Pick<SoarRun, 'trigger_kind'>): RunSource {
  if (run.trigger_kind === 'ai') return 'pivt';
  if (run.trigger_kind === 'manual') return 'user';
  return 'trigger';
}

/**
 * Who, in words: "you", the server display name (NAN-4544: current active
 * tenant members only), else the raw id.
 */
export function actorLabel(requestedBy: string | null | undefined, me: string | undefined, name?: string | null): string {
  if (!requestedBy || requestedBy === 'system') return 'system';
  if (me && requestedBy === me) return 'you';
  if (name) return name;
  return /^[0-9a-f-]{36}$/i.test(requestedBy) ? `user ${shortId(requestedBy)}` : requestedBy;
}

export function triggerWho(run: Pick<SoarRun, 'trigger_kind' | 'trigger_ref'>): string {
  switch (run.trigger_kind) {
    case 'alert': return run.trigger_ref ? `Alert committed · rule ${run.trigger_ref}` : 'Alert committed';
    case 'case': return run.trigger_ref ? `Case event · ${run.trigger_ref}` : 'Case event';
    case 'case_triage_verdict': return 'Case triage verdict';
    case 'schedule': return 'Schedule · UTC';
    default: return run.trigger_kind;
  }
}

export interface RunView {
  run: SoarRun;
  name: string;
  verb: string;
  effect: Effect | null;
  action: SoarCatalogAction | null;
  vendor: string | null;
  target: { kind: EntityKind; value: string } | null;
  source: RunSource;
  origin: OriginKind;
  who: string;
  outcome: Outcome;
  okey: OutcomeKey;
  duration: string;
  isChange: boolean;
  inverse: string | null;
  flow: SoarFlow | null;
}

export function shortTarget(v: string): string {
  return v.replace(/@acme\.io$/, '').replace(/^(?:sha256\s+)?([a-f0-9]{8})[a-f0-9]{40,}([a-f0-9]{4})$/i, '$1…$2');
}

export function runView(
  run: SoarRun,
  index: Map<string, IndexedAction>,
  opts: { me?: string; flows?: SoarFlow[]; steps?: SoarStepResult[]; now?: number } = {},
): RunView {
  const found = lookupAction(index, run.pack_name, run.action);
  const action = found?.action ?? null;
  const effect = run.action ? asEffect(action?.effect) : null;
  const flow = run.flow_id ? opts.flows?.find((f) => f.id === run.flow_id) ?? null : null;
  const target = run.action ? inputTargets(run.inputs, action ?? undefined, 1)[0] ?? null : null;
  const source = runSource(run);
  const name = run.action ? action?.display_name ?? run.action : flow?.name ?? (run.flow_id ? `Flow ${shortId(run.flow_id)}` : 'Run');
  const outcome = runOutcome(run, opts.steps);
  const who = source === 'trigger'
    ? triggerWho(run)
    : source === 'pivt'
      ? `pivt · on behalf of ${actorLabel(run.requested_by, opts.me, run.requested_by_name)}`
      : actorLabel(run.requested_by, opts.me, run.requested_by_name);
  const rollback = action?.rollback ? index.get(`${run.pack_name}.${action.rollback}`)?.action.display_name ?? verbOf(action.rollback) : null;
  return {
    run,
    name,
    verb: run.action ? verbOf(run.action, action?.display_name) : name,
    effect,
    action,
    vendor: found?.pack.display_name ?? run.pack_name,
    target: target ? { kind: target.kind, value: target.value } : null,
    source,
    origin: source === 'pivt' ? 'pivt' : source === 'trigger' ? 'trigger' : 'user',
    who,
    outcome,
    okey: outcomeKey(outcome),
    duration: run.started_at ? runDuration(run, opts.now) : '—',
    isChange: !run.dry_run && (effect === 'write' || effect === 'destructive'),
    inverse: rollback,
    flow,
  };
}

export const RUN_WORD: Partial<Record<OutcomeKey, [string, string]>> = {
  run: ['running', 'text-primary'],
  wait: ['waiting on approver', 'text-warn'],
  amb: ['unknown outcome', 'text-warn'],
  fail: ['failed', 'text-destructive'],
  rej: ['canceled', 'text-muted-foreground'],
};

// ── Trace spans ─────────────────────────────────────────────────────────

export type TraceKind = 'ok' | 'wait' | 'poll' | 'queue' | 'amb' | 'fail' | 'cancel' | 'none';

export interface TraceSpan {
  key: string;
  name: string;
  effect: Effect | null;
  kind: TraceKind;
  /** ms from the run's first step. */
  start: number;
  dur: number;
  at: string | null;
  note: string | null;
  step: SoarStepResult | null;
  iterations: SoarStepResult[];
  attempts: number;
  approval: SoarApproval | null;
  /** Connection id from the flow module (flow runs). */
  connection: string | null;
  /** Step approval policy from the flow module (default / required / auto). */
  policy: string | null;
  /** Pack-declared receipt polling for this action (NAN-4556). */
  poll: { interval_secs: number; max_secs: number } | null;
}

interface ModuleInfo { id: string; name: string; effect: Effect | null; approval: boolean; type: string; policy: string | null; connection: string | null; poll: TraceSpan['poll']; descendants: string[] }

/** Flatten a flow definition into module ids, in order, with display names. */
export function flowModules(definition: unknown, index: Map<string, IndexedAction>): ModuleInfo[] {
  const out: ModuleInfo[] = [];
  const walk = (mods: unknown): string[] => {
    const seen: string[] = [];
    if (!Array.isArray(mods)) return seen;
    for (const m of mods as Array<Record<string, unknown>>) {
      const v = (m?.value ?? {}) as Record<string, unknown>;
      const id = String(m?.id ?? '');
      const summary = typeof m?.summary === 'string' && m.summary ? m.summary : '';
      const type = String(v.type ?? '');
      let name = summary || id;
      let effect: Effect | null = null;
      let poll: TraceSpan['poll'] = null;
      if (type === 'action') {
        const f = lookupAction(index, v.pack as string, v.action as string);
        effect = asEffect(f?.action.effect);
        poll = f?.action.poll ?? null;
        name = `${f?.action.display_name ?? v.action} · ${f?.pack.vendor ?? v.pack}`;
      } else if (type === 'approval') name = summary || 'Approval';
      else if (type === 'branchone' || type === 'branchall') name = `Condition · ${summary || id}`;
      else if (type === 'forloopflow') name = `Loop · ${summary || id}`;
      else if (type === 'search') name = `Search · ${summary || id}`;
      else if (type === 'identity') name = summary || 'Pass-through';
      const info: ModuleInfo = { id, name, effect, approval: type === 'approval', type, policy: typeof v.approval === 'string' ? v.approval : null, connection: typeof v.connection === 'string' ? v.connection : null, poll, descendants: [] };
      out.push(info);
      seen.push(id);
      const kids: string[] = [];
      if (type === 'forloopflow') kids.push(...walk(v.modules));
      if (type === 'branchone') {
        for (const b of (v.branches as Array<{ modules: unknown }>) ?? []) kids.push(...walk(b.modules));
        kids.push(...walk(v.default));
      }
      if (type === 'branchall') for (const b of (v.branches as Array<{ modules: unknown }>) ?? []) kids.push(...walk(b.modules));
      info.descendants = kids;
      seen.push(...kids);
    }
    return seen;
  };
  const doc = definition as { value?: { modules?: unknown } } | null;
  walk(doc?.value?.modules);
  return out;
}

function stepKind(s: SoarStepResult): TraceKind {
  switch (s.status) {
    case 'succeeded': return 'ok';
    case 'failed':
    case 'timed_out': return 'fail';
    case 'awaiting_approval':
    case 'would_wait': return 'wait';
    case 'ambiguous': return 'amb';
    case 'canceled': return 'cancel';
    case 'skipped': return 'none';
    case 'running':
    case 'sending':
    case 'preparing': return s.phase === 'polling' || s.attempt > 1 ? 'poll' : 'poll';
    default: return 'queue';
  }
}

/**
 * Spans for the trace. Action runs (one `action` module) read as the mock:
 * an Approval span while (or after) a human gate, then the action itself.
 * Flow runs list every definition module, marking those not yet started.
 */
export function traceSpans(detail: SoarRunDetail, view: RunView, index: Map<string, IndexedAction>, now: number): { spans: TraceSpan[]; total: number; t0: number } {
  const steps = detail.steps ?? [];
  const approvals = detail.approvals ?? [];
  const t0 = steps.length ? Math.min(...steps.map((s) => s.started_at_ms)) : Date.parse(detail.started_at ?? detail.created_at);
  const end = (s: SoarStepResult) => s.finished_at_ms ?? (['ok', 'none'].includes(stepKind(s)) ? s.started_at_ms : now);
  const spans: TraceSpan[] = [];
  const mk = (p: Partial<TraceSpan> & Pick<TraceSpan, 'key' | 'name' | 'kind'>): TraceSpan => ({
    effect: null, start: 0, dur: 0, at: null, note: null, step: null, iterations: [], attempts: 1, approval: null, connection: null, policy: null, poll: null, ...p,
  });

  if (!detail.flow_id) {
    const step = steps.find((s) => s.module_id === 'action') ?? steps[0] ?? null;
    // The gate that let this attempt through: the last decision before it started.
    const decided = approvals.filter((a) => a.decided_at && (!step || Date.parse(a.decided_at) <= step.started_at_ms + 1000));
    const approval = step && (step.status === 'awaiting_approval' || step.status === 'would_wait')
      ? approvals.find((a) => a.status === 'pending') ?? approvals[approvals.length - 1] ?? null
      : decided[decided.length - 1] ?? null;
    const actionName = view.action?.display_name ?? detail.action ?? 'Action';
    if (!step) {
      spans.push(mk({ key: 'queued', name: 'Queued', kind: 'queue', note: detail.executor_pending ? 'accepted · waiting for an executor' : 'queued' }));
      spans.push(mk({ key: 'action', name: actionName, kind: 'none', effect: view.effect }));
    } else if (step.status === 'awaiting_approval' || step.status === 'would_wait') {
      spans.push(mk({ key: 'approval', name: 'Approval', kind: 'wait', start: step.started_at_ms - t0, dur: now - step.started_at_ms, at: step.started_at, step, approval, note: `waiting · ${step.started_at.slice(11, 19)}` }));
      spans.push(mk({ key: 'action', name: actionName, kind: 'none', effect: view.effect, start: now - t0 }));
    } else {
      if (approval && approval.decided_at) {
        const a0 = Date.parse(approval.created_at);
        const a1 = Date.parse(approval.decided_at);
        spans.push(mk({ key: 'approval', name: 'Approval', kind: approval.status === 'approved' ? 'wait' : 'fail', start: Math.max(0, a0 - t0), dur: Math.max(0, a1 - a0), at: approval.created_at, approval,
          note: approval.status === 'approved' ? `Approved by ${actorLabel(approval.decided_by, undefined, approval.decided_by_name)}` : `${approval.status} · ${approval.decided_at.slice(11, 19)}` }));
      }
      const k = stepKind(step);
      const tZero = Math.min(t0, approval ? Date.parse(approval.created_at) : t0);
      spans.push(mk({ key: step.id, name: actionName, kind: k, effect: view.effect, start: step.started_at_ms - tZero, dur: end(step) - step.started_at_ms, at: step.started_at, step, attempts: step.attempt, poll: view.action?.poll ?? null,
        note: stepNote(step, k) }));
      if (tZero !== t0) for (const s of spans) if (s.key === 'approval') s.start = 0;
    }
  } else {
    const mods = flowModules(view.flow?.definition, index);
    const byModule = new Map<string, SoarStepResult[]>();
    for (const s of steps) byModule.set(s.module_id, [...(byModule.get(s.module_id) ?? []), s]);
    if (detail.trigger_kind !== 'manual') {
      spans.push(mk({ key: 'trigger', name: `Trigger · ${detail.trigger_kind === 'alert' ? 'alert committed' : detail.trigger_kind.replace(/_/g, ' ')}`, kind: 'ok', start: 0, dur: 0, at: detail.created_at, note: detail.trigger_ref }));
    }
    const ids = mods.length ? mods.map((m) => m.id) : [...byModule.keys()];
    for (const id of ids) {
      const info = mods.find((m) => m.id === id);
      const own = byModule.get(id) ?? [];
      // Loops and branches record no step of their own: read them from their children.
      const group = own.length ? own : (info?.descendants ?? []).flatMap((d) => byModule.get(d) ?? []);
      if (group.length === 0) {
        spans.push(mk({ key: id, name: info?.name ?? id, kind: 'none', effect: info?.effect ?? null, note: 'not started', connection: info?.connection ?? null }));
        continue;
      }
      const first = group.reduce((a, b) => (b.started_at_ms < a.started_at_ms ? b : a));
      const last = group[group.length - 1];
      const container = own.length === 0;
      const iter = !container && (group.length > 1 || group.some((g) => g.iteration != null));
      const k = group.some((g) => stepKind(g) === 'fail') ? 'fail' : group.some((g) => stepKind(g) === 'amb') ? 'amb' : stepKind(last);
      const kind: TraceKind = info?.approval && k === 'ok' ? 'wait' : k;
      const approval = approvals.find((a) => a.module_id === id) ?? null;
      const loopCount = info?.type === 'forloopflow' ? Math.max(0, ...group.map((g) => (typeof g.iteration === 'number' ? g.iteration + 1 : 1))) : 0;
      spans.push(mk({
        key: id,
        name: (info?.name ?? id) + (iter ? ` (${group.length})` : loopCount ? ` (${loopCount})` : ''),
        kind, effect: info?.effect ?? null,
        start: first.started_at_ms - t0, dur: Math.max(...group.map(end)) - first.started_at_ms, at: first.started_at, step: container ? null : last,
        iterations: iter ? group : [], attempts: Math.max(...group.map((g) => g.attempt)), approval, connection: info?.connection ?? null, policy: info?.policy ?? null, poll: info?.poll ?? null,
        note: info?.approval
          ? approval?.decided_by ? `Approved by ${actorLabel(approval.decided_by, undefined, approval.decided_by_name)}` : last.status === 'succeeded' ? 'approved' : stepNote(last, kind)
          : container ? (info?.type === 'branchone' ? 'branch taken' : null) : stepNote(last, kind),
      }));
    }
  }
  const total = Math.max(10_000, ...spans.map((s) => (s.start + s.dur) * 1.08));
  return { spans, total, t0 };
}

function stepNote(s: SoarStepResult, k: TraceKind): string | null {
  if (k === 'amb') return 'sent · no response';
  if (k === 'poll') return `polling · attempt ${s.attempt}`;
  if (k === 'fail') return s.error_class ? s.error_class.replace(/_/g, ' ') : 'failed';
  if (k === 'cancel') return s.skip_reason ?? 'canceled';
  if (k === 'wait') return `waiting · ${s.started_at.slice(11, 19)}`;
  const d = s.finished_at_ms != null ? formatDuration(s.finished_at_ms - s.started_at_ms) : null;
  return d;
}

/** "+1m 44s" style axis label from ms. */
export function fmtS(ms: number): string {
  const s = ms / 1000;
  if (s < 1) return `${Math.round(ms)}ms`;
  if (s < 60) return `${Math.round(s)}s`;
  const r = Math.round(s % 60);
  return `${Math.floor(s / 60)}m${r ? ` ${r}s` : ''}`;
}

/** Mock decisionBlock: short + long wording for why the user cannot decide. */
export function blockWords(block: string, approval: SoarApproval): { short: string; long: string } {
  switch (block) {
    case 'Expired': return { short: 'Expired', long: `Expired at ${approval.expires_at.slice(11, 19)} UTC. The run stopped waiting and will not execute.` };
    case 'Already decided': return { short: 'Decided', long: `This was ${approval.status}${approval.decided_at ? ` at ${approval.decided_at.slice(11, 19)} UTC` : ''}.` };
    case 'Read-only demo': return { short: 'Demo', long: 'Read-only demo. Decisions are disabled.' };
    case 'Requires soar:approve': return { short: 'No soar:approve', long: 'You need soar:approve to decide approvals. Ask a tenant admin.' };
    default: return { short: 'Your request', long: 'You requested this action. Self-approval is prohibited; another approver must decide.' };
  }
}
