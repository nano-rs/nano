// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — the mock's "test with sample" overlay, sourced from a real dry
 * run of the flow (POST /api/soar/flows/:id/run with dry_run). Per-step
 * results come from the run's step rows, keyed by module id.
 */
import type { SoarRunDetail, SoarStepResult } from '@/lib/api/soar';
import type { FlowDoc } from './flow-editor-model';
import { childLists, typeOf, walk } from './flow-editor-model';
import { formatDuration } from './soar-model';

export type TestState = 'ok' | 'fail' | 'skip' | 'wait';
export interface TestResult {
  st: TestState;
  m: string;
  out?: string;
}

const OK = new Set(['succeeded', 'would_wait']);
const FAIL = new Set(['failed', 'timed_out', 'ambiguous', 'canceled']);

function stateOf(steps: SoarStepResult[]): TestState {
  if (steps.some((s) => FAIL.has(s.status))) return 'fail';
  if (steps.every((s) => s.status === 'skipped')) return 'skip';
  if (steps.every((s) => OK.has(s.status) || s.status === 'skipped')) return 'ok';
  return 'wait';
}

function outputText(outputs: unknown): string | undefined {
  if (outputs === null || outputs === undefined) return undefined;
  if (typeof outputs !== 'object') return String(outputs);
  const entries = Object.entries(outputs as Record<string, unknown>);
  if (entries.length === 0) return undefined;
  const pad = Math.max(...entries.map(([k]) => k.length)) + 1;
  return entries.map(([k, v]) => `${(k + ':').padEnd(pad + 1)}${typeof v === 'string' ? v : JSON.stringify(v)}`).join('\n');
}

export function testResults(run: SoarRunDetail | undefined, doc: FlowDoc): { results: Record<string, TestResult>; taken: Map<string, number | 'default' | null> } {
  const results: Record<string, TestResult> = {};
  const taken = new Map<string, number | 'default' | null>();
  if (!run) return { results, taken };
  const byModule = new Map<string, SoarStepResult[]>();
  for (const s of run.steps) byModule.set(s.module_id, [...(byModule.get(s.module_id) ?? []), s]);
  results.trigger = { st: 'ok', m: run.trigger_kind === 'manual' ? 'started manually' : `matched ${run.trigger_kind}` };
  const ran = (id: string): boolean => byModule.has(id);
  walk(doc, ({ mod }) => {
    const steps = byModule.get(mod.id) ?? [];
    const kids = childLists(mod);
    if (typeOf(mod) === 'forloopflow') {
      const iterations = new Set(kids.flatMap((c) => c.list.flatMap((k) => (byModule.get(k.id) ?? []).map((s) => JSON.stringify(s.iteration)))));
      if (iterations.size > 0 || steps.length > 0) results[mod.id] = { st: steps.length ? stateOf(steps) : 'ok', m: `${iterations.size} item${iterations.size === 1 ? '' : 's'}` };
      return;
    }
    if (typeOf(mod) === 'branchone') {
      const hit = kids.find((c) => c.list.some((k) => ran(k.id)));
      taken.set(mod.id, hit ? hit.ref.slot as number | 'default' : null);
      if (steps.length || hit) results[mod.id] = { st: steps.length ? stateOf(steps) : 'ok', m: hit ? (hit.ref.slot === 'default' ? '→ else' : `→ ${hit.label}`) : 'evaluated' };
      return;
    }
    if (steps.length === 0) return;
    const st = stateOf(steps);
    const multi = steps.length > 1 && steps.some((s) => s.iteration !== null && s.iteration !== undefined);
    const dur = steps.reduce((n, s) => n + ((s.finished_at_ms ?? s.started_at_ms) - s.started_at_ms), 0);
    const okN = steps.filter((s) => OK.has(s.status)).length;
    const m = st === 'skip'
      ? steps[0].skip_reason ?? 'skipped'
      : multi ? `${okN}/${steps.length} ok` : `${formatDuration(dur)}${run.dry_run ? ' · dry run' : ''}`;
    results[mod.id] = { st, m, out: outputText(steps[steps.length - 1].outputs) };
  });
  return { results, taken };
}
