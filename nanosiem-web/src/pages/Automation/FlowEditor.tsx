// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — flow editor (port of soar3-flow.jsx FlowEditor3): block palette,
 * vertical spine with drag-and-drop insert / reorder, step inspector, undo,
 * duplicate / delete, server validation with findings on the steps, and save
 * through PUT /api/soar/flows/:id.
 *
 * Editable when the user holds soar:manage, is not a demo principal, and the
 * flow is draft or live (saving a live flow changes it in place — the backend
 * keeps one version per flow, so there is no "v8 draft beside live v7").
 * Archived flows are read-only until restored.
 */
import { useCallback, useEffect, useMemo, useReducer, useRef, useState, type KeyboardEvent, type ReactElement, type ReactNode } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, Copy, Play, Plus, Trash2, Undo2, X } from 'lucide-react';
import { api } from '@/lib/api';
import type { SoarFlow, SoarFlowTrigger } from '@/lib/api/soar';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { cn } from '@/lib/utils';
import type { ContainerRef, DragItem, DropAt, FlowDoc, NewSpec, RawModule } from './flow-editor-model';
import {
  LIMITS,
  ROOT,
  afterStep,
  getList,
  canDrop,
  hasCondition,
  duplicateModule,
  insertAt,
  localFindings,
  locate,
  makeModule,
  maxDepth,
  moduleCount,
  moveTo,
  nudge,
  allIds,
  removeModule,
  serverFindings,
  staticNumber,
  toDoc,
  typeOf,
  updateModule,
  walk,
  type Finding,
} from './flow-editor-model';
import { testResults } from './flow-test-results';
import { FlowCanvas, Res, type CanvasModel, type Dnd } from './FlowCanvas';
import { FlowInspector } from './FlowInspector';
import { FlowBlockPicker } from './FlowBlockPicker';
import { FlowPalette, blockEntries, type BlockEntry } from './FlowPalette';
import { RunFlowDialog } from './FlowRunDialog';
import { Banner, GatedButton, H, PAGE_TITLE, Spinner, StatusPill } from './soar-kit';
import { triggerKind } from './soar-fields';
import { actionIndex, shortId, utcTime } from './soar-model';
import { effectErrorMessage, errorStatus, invalidateSoar, soarKeys, useCatalog, useConnections, useRun, useRuns } from './soar-queries';
import { useFlowPivt, useJudgeBlock, useSoarGate } from './soar-gate';
import { judgeScopeFindings } from './soar-fields';
import { useRegisterEditableArtifact } from '@/contexts/EditableArtifactContext';

interface Snap {
  doc: FlowDoc;
  trigger: SoarFlowTrigger;
}
interface EdState extends Snap {
  past: Snap[];
  /** Coalesces consecutive keystrokes in one field into one undo step. */
  key: string | null;
}
type EdAction =
  | { type: 'reset'; snap: Snap }
  | { type: 'apply'; next: Partial<Snap>; key?: string | null }
  | { type: 'undo' };

function reducer(s: EdState, a: EdAction): EdState {
  switch (a.type) {
    case 'reset':
      return { ...a.snap, past: [], key: null };
    case 'apply': {
      const next = { doc: a.next.doc ?? s.doc, trigger: a.next.trigger ?? s.trigger };
      if (next.doc === s.doc && next.trigger === s.trigger) return s;
      const coalesce = !!a.key && a.key === s.key;
      return { ...next, past: coalesce ? s.past : [...s.past, { doc: s.doc, trigger: s.trigger }].slice(-100), key: a.key ?? null };
    }
    case 'undo': {
      const prev = s.past[s.past.length - 1];
      return prev ? { ...prev, past: s.past.slice(0, -1), key: null } : s;
    }
  }
}

function snapOf(f: Pick<SoarFlow, 'definition' | 'trigger' | 'name'>): Snap {
  return { doc: toDoc(f.definition, f.name), trigger: { on: f.trigger?.on ?? 'manual', match: f.trigger?.match ?? null, cron: f.trigger?.cron ?? null } };
}

/** NAN-4653: the document pivt edits — what the editor would save. */
export interface FlowEditDoc {
  name: string;
  trigger: SoarFlowTrigger;
  definition: FlowDoc;
}

/** How long pivt's changed steps stay highlighted. */
export const PIVT_GLOW_MS = 4000;
const sig = (s: Snap) => JSON.stringify([s.doc, s.trigger]);

function isTyping(t: EventTarget | null): boolean {
  const el = t as HTMLElement | null;
  return !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
}

export function FlowEditor({ flow, notice }: { flow: SoarFlow; notice?: ReactNode }) {
  const gate = useSoarGate();
  const { hasPermission } = useAuth();
  const client = useQueryClient();
  const enabled = gate.state === 'enabled';
  const catalog = useCatalog(gate.tenant, enabled);
  const connections = useConnections(gate.tenant, enabled && !gate.demo);
  const runs = useRuns(gate.tenant, enabled);
  const index = useMemo(() => actionIndex(catalog.data), [catalog.data]);
  const ctx = useMemo(() => ({ index, connections: connections.data?.connections ?? [] }), [index, connections.data]);

  const canManage = !gate.demo && hasPermission('soar:manage');
  const canRun = !gate.demo && hasPermission('soar:run');
  const judgeOff = useJudgeBlock();

  // Baseline = what the server holds (version, status, saved content).
  const [base, setBase] = useState(() => ({ snap: snapOf(flow), version: flow.version, status: flow.status, name: flow.name }));
  const [ed, dispatch] = useReducer(reducer, base.snap, (snap) => ({ ...snap, past: [], key: null }));
  const dirty = sig(ed) !== sig(base.snap);
  const ro = !canManage || base.status === 'archived';

  // A newer server version replaces the editor only while there are no local edits.
  useEffect(() => {
    if (flow.version !== base.version && !dirty) {
      const snap = snapOf(flow);
      setBase({ snap, version: flow.version, status: flow.status, name: flow.name });
      dispatch({ type: 'reset', snap });
    } else if (flow.version === base.version && flow.status !== base.status) {
      setBase((b) => ({ ...b, status: flow.status }));
    }
  }, [flow, base.version, base.status, dirty]);

  const local = useMemo(() => [...localFindings(ed.doc, ed.trigger, ctx), ...judgeScopeFindings(ed.doc, ed.trigger.on)], [ed.doc, ed.trigger, ctx]);
  const [validated, setValidated] = useState<{ sig: string; ok: boolean; findings: Finding[]; summary?: string } | null>(null);
  const current = sig(ed);
  const v = validated && validated.sig === current ? validated : null;
  const findings = v ? v.findings : local;
  const errors = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const f of [...local, ...(v?.findings ?? [])]) if (f.step) m.set(f.step, [...new Set([...(m.get(f.step) ?? []), f.message])]);
    return m;
  }, [local, v]);

  // Open on the first step that needs attention (mock opens s6), once the catalog is known.
  const [sel, setSel0] = useState<string | null>(null);
  const [pal, setPal0] = useState(false);
  const touched = useRef(false);
  useEffect(() => {
    if (touched.current || !catalog.data || (connections.isPending && !gate.demo)) return;
    touched.current = true;
    // Narrow screens overlay the inspector; open it only on request there.
    if ((rootRef.current?.clientWidth ?? 1400) < 1180) return;
    const first = local.find((f) => f.step && f.step !== 'trigger')?.step;
    setSel0(first ?? 'trigger');
  }, [catalog.data, connections.isPending, gate.demo, local]);
  const setSel = (id: string | null) => { touched.current = true; setSel0(id); if (id) setPal0(false); };
  // NAN-4661: opening the palette hides the inspector; the step that was
  // selected stays the palette's insertion point ("adds after the selected step").
  const [palAnchor, setPalAnchor] = useState<string | null>(null);
  const setPal = (p: boolean) => {
    touched.current = true;
    setPal0(p);
    if (p) { setPalAnchor(sel && sel !== 'trigger' ? sel : null); setSel0(null); }
  };

  // Layout modes (mock: overlay < 1180 root, stack < 600 canvas, compact).
  const rootRef = useRef<HTMLDivElement>(null);
  const canRef = useRef<HTMLDivElement>(null);
  const [rw, setRw] = useState(1400);
  const [cw, setCw] = useState(900);
  useEffect(() => {
    if (typeof ResizeObserver === 'undefined') return;
    const ob = new ResizeObserver(() => {
      if (rootRef.current) setRw(rootRef.current.clientWidth);
      if (canRef.current) setCw(canRef.current.clientWidth);
    });
    if (rootRef.current) ob.observe(rootRef.current);
    if (canRef.current) ob.observe(canRef.current);
    return () => ob.disconnect();
  }, []);
  const overlay = rw < 1180;
  const stack = cw < 600;
  const compact = stack ? cw < 420 : cw < 820;

  const apply = useCallback((next: Partial<Snap>, key?: string | null) => dispatch({ type: 'apply', next, key }), []);
  const undo = useCallback(() => dispatch({ type: 'undo' }), []);

  // ── pivt conversational edit (NAN-4653) ───────────────────────────────
  // Register the open flow with the pivt panel while it is editable and the
  // user may use pivt on it. A finished turn lands as ONE undo step (the
  // reducer's `apply` with no coalescing key) and its changed steps glow for
  // a few seconds. pivt never saves or activates: those stay on this page.
  const pivtOk = useFlowPivt(gate.demo);
  const [glow, setGlow] = useState<{ ids: ReadonlySet<string>; n: number } | null>(null);
  useEffect(() => {
    if (!glow) return;
    const t = setTimeout(() => setGlow((g) => (g?.n === glow.n ? null : g)), PIVT_GLOW_MS);
    return () => clearTimeout(t);
  }, [glow]);
  useRegisterEditableArtifact<FlowEditDoc>(
    pivtOk && !ro
      ? {
          kind: 'flow',
          id: flow.id,
          version: base.version,
          name: base.name,
          noun: 'flow',
          getDoc: () => ({ name: base.name, trigger: ed.trigger, definition: { ...ed.doc, summary: ed.doc.summary || base.name } }),
          apply: (doc, changed) => {
            const next = snapOf({ definition: doc.definition, trigger: doc.trigger, name: base.name });
            apply(next, null);
            setGlow((g) => ({ ids: new Set(changed), n: (g?.n ?? 0) + 1 }));
          },
          history: { depth: () => ed.past.length, undo },
        }
      : null,
  );

  useEffect(() => {
    const k = (e: globalThis.KeyboardEvent) => {
      // NAN-4586: an Escape that closed a menu or suggestion list stays there.
      if (e.key === 'Escape' && !e.defaultPrevented) { setSel0(null); setPal0(false); }
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && e.key.toLowerCase() === 'z' && !isTyping(e.target) && !ro) {
        e.preventDefault();
        undo();
      }
    };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [undo, ro]);

  // ── Structure edits ───────────────────────────────────────────────────
  // NAN-4661: the lane whose "add to …" picker was last used.
  const [lastLane, setLastLane] = useState<ContainerRef | null>(null);
  /** Where a palette click inserts: after the selected step, else the last
   *  "add to" lane, else the end of the root list. Never implicitly `then`. */
  const paletteAt = (): DropAt => {
    const anchor = sel && sel !== 'trigger' ? sel : !sel && pal ? palAnchor : null;
    const after = anchor ? afterStep(ed.doc, anchor) : null;
    if (after) return after;
    if (lastLane && getList(ed.doc, lastLane)) return { ref: lastLane, before: null };
    return { ref: ROOT, before: null };
  };

  /** `exact`: the picker inserts at its slot or not at all; a palette click falls back to the root end. */
  const insertNew = (spec: NewSpec, at: DropAt, exact = false) => {
    if (ro || (spec.block === 'judge' && judgeOff)) return;
    const item: DragItem = { kind: 'new', spec, label: spec.block };
    const end: DropAt = { ref: ROOT, before: null };
    const target = canDrop(ed.doc, item, at) ? at : !exact && canDrop(ed.doc, item, end) ? end : null;
    if (!target) return;
    const m = makeModule(spec, ctx, allIds(ed.doc));
    apply({ doc: insertAt(ed.doc, [m], target) });
    setSel0(m.id);
    setPalAnchor(null);
  };
  /** Palette entries for one slot, with why a block cannot go there. */
  const entriesAt = (at: DropAt): BlockEntry[] =>
    blockEntries(catalog.data, ctx.connections, hasCondition(ed.doc), judgeOff).map((x) => {
      if (x.off || canDrop(ed.doc, { kind: 'new', spec: x.spec, label: x.label }, at)) return x;
      const why = moduleCount(ed.doc) >= LIMITS.modules
        ? `Flow is at the ${LIMITS.modules}-step limit`
        : x.spec.block === 'condition' ? 'Only at the top level' : x.spec.block === 'loop' ? 'Not inside a loop or this deep' : `Max depth ${LIMITS.depth}`;
      return { ...x, off: why };
    });
  const addPicker = (at: DropAt, label: string, button: ReactElement) => (
    <FlowBlockPicker
      label={label}
      entries={() => entriesAt(at)}
      onPick={(x) => { setLastLane(at.ref); insertNew(x.spec, at, true); }}
    >
      {button}
    </FlowBlockPicker>
  );
  const setTriggerOn = (on: string) => {
    if (ro) return;
    const t: SoarFlowTrigger = on === 'schedule' ? { on, cron: ed.trigger.cron || '0 0 */6 * * * *', match: null } : on === 'manual' ? { on, match: null, cron: null } : { on, match: ed.trigger.match ?? null, cron: null };
    apply({ trigger: t });
    setSel0('trigger');
  };

  const [drag, setDrag] = useState<DragItem | null>(null);
  const dnd: Dnd = {
    drag,
    ro,
    start: (d) => setDrag(d),
    end: () => setDrag(null),
    ok: (at) => canDrop(ed.doc, drag, at),
    drop: (at) => {
      const d = drag;
      setDrag(null);
      if (!d || !canDrop(ed.doc, d, at)) return;
      if (d.kind === 'new') {
        const m = makeModule(d.spec, ctx, allIds(ed.doc));
        apply({ doc: insertAt(ed.doc, [m], at) });
        setSel0(m.id);
      } else if (d.kind === 'move') {
        apply({ doc: moveTo(ed.doc, d.id, at) });
        setSel0(d.id);
      }
    },
    dropTrigger: () => {
      const d = drag;
      setDrag(null);
      if (d?.kind === 'trigger') setTriggerOn(d.on);
    },
  };

  const del = (id: string) => {
    if (ro) return;
    apply({ doc: removeModule(ed.doc, id) });
    setSel0(null);
  };
  const dup = (id: string) => {
    if (ro || moduleCount(ed.doc) >= LIMITS.modules) return;
    const r = duplicateModule(ed.doc, id);
    if (r.id) { apply({ doc: r.doc }); setSel0(r.id); }
  };
  const move = (id: string, dir: -1 | 1) => { if (!ro) apply({ doc: nudge(ed.doc, id, dir) }); };
  const onBlockKey = (id: string, e: KeyboardEvent) => {
    if (ro) return;
    if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); del(id); }
    else if (e.altKey && e.key === 'ArrowUp') { e.preventDefault(); move(id, -1); }
    else if (e.altKey && e.key === 'ArrowDown') { e.preventDefault(); move(id, 1); }
    else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'd') { e.preventDefault(); dup(id); }
  };

  // ── Server calls ──────────────────────────────────────────────────────
  const validate = useMutation({
    mutationFn: () => api.soar.validateFlow(ed.doc, triggerKind(ed.trigger.on)),
    onSuccess: (res) => {
      const server = (res.findings ?? []).flatMap((m) => serverFindings(m, ed.doc));
      setValidated({ sig: current, ok: res.valid && local.length === 0 && server.length === 0, findings: [...local, ...server], summary: `${res.summary} · ${res.module_count} modules` });
    },
    onError: (err) => setValidated({ sig: current, ok: false, findings: [...local, ...serverFindings(effectErrorMessage(err, 'Validation failed.'), ed.doc)] }),
  });
  const [confirmLiveSave, setConfirmLiveSave] = useState(false);
  const save = useMutation({
    mutationFn: () => api.soar.updateFlow(flow.id, { expected_version: base.version, name: base.name, definition: { ...ed.doc, summary: ed.doc.summary || base.name }, trigger: ed.trigger, status: base.status }),
    onSuccess: (res) => {
      setBase({ snap: { doc: ed.doc, trigger: ed.trigger }, version: res.version, status: res.status, name: res.name });
      if (validated?.sig === current) setValidated({ ...validated, sig: sig({ doc: ed.doc, trigger: ed.trigger }) });
      client.setQueryData(soarKeys.flow(gate.tenant, flow.id), res);
      void client.invalidateQueries({ queryKey: soarKeys.flows(gate.tenant) });
    },
  });
  const conflict = save.isError && errorStatus(save.error) === 409;
  const reloadLatest = async () => {
    const latest = await api.soar.getFlow(flow.id);
    client.setQueryData(soarKeys.flow(gate.tenant, flow.id), latest);
    const snap = snapOf(latest);
    setBase({ snap, version: latest.version, status: latest.status, name: latest.name });
    dispatch({ type: 'reset', snap });
    save.reset();
  };
  const [statusTarget, setStatusTarget] = useState<null | 'live' | 'archived' | 'draft'>(null);
  const setStatus = useMutation({
    mutationFn: (status: string) => api.soar.updateFlow(flow.id, { expected_version: base.version, name: base.name, definition: flow.definition, trigger: flow.trigger, status }),
    onSuccess: (res) => setBase((b) => ({ ...b, version: res.version, status: res.status })),
    onSettled: () => void invalidateSoar(client, gate.tenant),
  });
  const [runDialog, setRunDialog] = useState<null | 'run' | 'dry'>(null);

  // ── Test overlay: the latest dry run of this flow ─────────────────────
  const dryRuns = useMemo(() => (runs.data?.runs ?? []).filter((r) => r.flow_id === flow.id && r.dry_run), [runs.data, flow.id]);
  const [testId, setTestId] = useState<string | null>(null);
  const tid = testId ?? dryRuns[0]?.id ?? null;
  const testRun = useRun(gate.tenant, tid ?? undefined, enabled && !!tid);
  const T = testRun.data && !dirty ? testRun.data : undefined;
  const { results, taken } = useMemo(() => testResults(T, ed.doc), [T, ed.doc]);
  const rs = Object.entries(results).filter(([k, r]) => k !== 'trigger' && r.st !== 'skip');
  const okN = rs.filter(([, r]) => r.st === 'ok').length;

  // ── Header numbers ────────────────────────────────────────────────────
  const count = moduleCount(ed.doc);
  const depth = maxDepth(ed.doc);
  let gates = 0;
  let loopPar: number | null = null;
  walk(ed.doc, ({ mod }) => {
    if (typeOf(mod) === 'approval') gates++;
    if (typeOf(mod) === 'forloopflow') loopPar = Math.max(loopPar ?? 0, mod.value.parallel ? staticNumber(mod.value.parallelism) ?? 1 : 1);
  });
  const lim = (l: string, n: number, max: number) => <span key={l} className={n > max ? 'text-destructive' : ''}>{l} {n}/{max}</span>;

  const s = sel && sel !== 'trigger' ? locate(ed.doc, sel)?.mod ?? null : null;
  const updModule = (fn: (m: RawModule) => void, key: string) => {
    if (!s || ro) return;
    apply({ doc: updateModule(ed.doc, s.id, fn) }, `${s.id}:${key}`);
  };
  const canActivate = v?.ok && !dirty;
  const activateReason = dirty ? 'Save first' : !v?.ok ? 'Validate with no errors first' : undefined;

  const model: CanvasModel = {
    // While the palette hides the inspector, its insertion point stays outlined.
    doc: ed.doc, trigger: ed.trigger, ctx, sel: sel ?? (pal ? palAnchor : null), select: (id) => setSel(id), errors, results, taken: T ? taken : undefined,
    dnd, ro, compact, stack, addPicker, onBlockKey, glow: glow?.ids,
  };

  return (
    <div ref={rootRef} className="flex h-full min-h-0 flex-col" data-testid="flow-editor">
      <div className="flex flex-wrap items-end gap-3 border-b border-border px-5 pb-3 pt-4">
        <div className="min-w-0">
          <h1 className={cn(PAGE_TITLE, 'flex items-center gap-2.5')}>
            {base.name}
            <StatusPill s={base.status} className="text-[11.5px] font-normal" />
            {dirty && <span className="text-[11px] font-normal text-warn">unsaved</span>}
          </h1>
          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-0.5 font-mono text-[11px] text-muted-foreground [&>*]:whitespace-nowrap">
            <span>
              v{base.version}
              {base.status === 'live' ? ' live · saving changes the live flow' : base.status === 'archived' ? ' archived · read-only' : ' draft'}
            </span>
            {lim('modules', count, LIMITS.modules)}
            {lim('depth', depth, LIMITS.depth)}
            {loopPar !== null && lim('loop ×', loopPar, LIMITS.parallelism)}
            <span>{gates} gate</span>
            {T ? (
              <span className={okN < rs.length ? 'text-destructive' : 'text-good'}>last test {utcTime(T.created_at).slice(0, 5)} · {okN}/{rs.length} ok</span>
            ) : (
              <span>{dirty && tid ? 'edited since last test' : 'not tested'}</span>
            )}
          </div>
        </div>
        <span className="flex-1" />
        {!gate.demo && (
          <div className="flex min-w-0 flex-wrap items-center gap-2 whitespace-nowrap">
            <span className="font-mono text-[10.5px] text-muted-foreground">test with</span>
            <div className="w-[220px]">
              <Select value={tid ?? '__none'} onValueChange={(x) => setTestId(x === '__none' ? null : x)} disabled={dryRuns.length === 0}>
                <SelectTrigger aria-label="Test run" className="h-8 font-mono text-[11px] shadow-none"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {dryRuns.length === 0 && <SelectItem value="__none" className="font-mono text-[11px]">no dry runs yet</SelectItem>}
                  {dryRuns.map((r) => <SelectItem key={r.id} value={r.id} className="font-mono text-[11px]">{shortId(r.id)} · {utcTime(r.created_at).slice(0, 5)} · {r.status === 'succeeded' ? 'ok' : r.status.replace('_', ' ')}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <GatedButton allowed={canRun} why="Requires soar:run" size="sm" variant="outline" disabled={base.status === 'archived'} reason="Archived flows do not run" onClick={() => setRunDialog('dry')}>
              <Play className="h-3 w-3" strokeWidth={1.5} />Run test
            </GatedButton>
            <GatedButton allowed={canManage} why="Requires soar:manage" size="sm" variant="ghost" disabled={validate.isPending} onClick={() => validate.mutate()}>
              {validate.isPending ? <><Spinner />Validating…</> : 'Validate'}
            </GatedButton>
            <GatedButton allowed={canManage} why="Requires soar:manage" size="sm" variant="outline" disabled={ro || !dirty || save.isPending} reason={base.status === 'archived' ? 'Archived flows are read-only' : 'No changes to save'} onClick={() => (base.status === 'live' ? setConfirmLiveSave(true) : save.mutate())}>
              {save.isPending ? <><Spinner />Saving…</> : base.status === 'live' ? 'Save' : 'Save draft'}
            </GatedButton>
            {base.status === 'draft' && (
              <GatedButton allowed={canManage} why="Requires soar:manage" size="sm" disabled={!canActivate} reason={activateReason} onClick={() => setStatusTarget('live')}>Activate</GatedButton>
            )}
            {base.status === 'live' && (
              <GatedButton allowed={canManage} why="Requires soar:manage" size="sm" variant="ghost" onClick={() => setStatusTarget('archived')}>Archive</GatedButton>
            )}
            {base.status === 'archived' && (
              <GatedButton allowed={canManage} why="Requires soar:manage" size="sm" variant="outline" onClick={() => setStatusTarget('draft')}>Restore as draft</GatedButton>
            )}
            {base.status !== 'archived' && (
              <GatedButton allowed={canRun} why="Requires soar:run" size="sm" variant="ghost" onClick={() => setRunDialog('run')}>Run</GatedButton>
            )}
          </div>
        )}
      </div>
      <div className="relative grid min-h-0 flex-1" style={{ gridTemplateColumns: (pal ? '250px ' : '') + 'minmax(0,1fr)' + (sel && !overlay ? ' 340px' : '') }}>
        {pal && (
          <FlowPalette ro={ro} dnd={dnd} catalog={catalog.data} connections={ctx.connections} hasCondition={hasCondition(ed.doc)} judgeOff={judgeOff} onAdd={(spec) => insertNew(spec, paletteAt())} onTrigger={setTriggerOn} />
        )}
        <div ref={canRef} className="flex min-w-0 flex-col gap-3 overflow-auto p-5">
          <div className="flex items-center gap-2">
            <Button size="sm" variant={pal ? 'secondary' : 'outline'} className="shadow-none" aria-pressed={pal} onClick={() => setPal(!pal)}>
              <Plus className="h-3 w-3" strokeWidth={1.5} />Blocks
            </Button>
            {!ro && (
              <Button size="sm" variant="ghost" className="shadow-none" disabled={ed.past.length === 0} onClick={undo} title="Undo (⌘Z / Ctrl+Z)" aria-label="Undo">
                <Undo2 className="h-3 w-3" strokeWidth={1.5} />Undo
              </Button>
            )}
            <span className="min-w-0 truncate font-mono text-[10.5px] text-muted-foreground">{ro ? 'read-only · click to inspect' : 'drag to reorder · click to edit'}</span>
          </div>
          {notice}
          {conflict && (
            <Banner tone="danger" title="Someone else saved this flow" action={<Button size="sm" variant="outline" className="h-7 shadow-none" onClick={() => void reloadLatest()}>Load latest</Button>}>
              Your edits were not saved. Loading the latest version discards them.
            </Banner>
          )}
          {save.isError && !conflict && (
            <Banner tone="danger" title="Save failed">{effectErrorMessage(save.error, 'The flow could not be saved.')}</Banner>
          )}
          {setStatus.isError && <Banner tone="danger" title="Status change failed">{effectErrorMessage(setStatus.error, 'The flow could not be updated.')}</Banner>}
          {v && !v.ok && (
            <Banner tone="danger" title={`${findings.length} validation error${findings.length === 1 ? '' : 's'}`}>
              <div data-testid="validation-findings">
                {findings.map((f, i) => (
                  <div key={i}>
                    {f.step && <button type="button" className="mr-1.5 font-mono text-primary hover:underline" onClick={() => setSel(f.step)}>{f.step}</button>}
                    {f.message}
                  </div>
                ))}
              </div>
            </Banner>
          )}
          {v?.ok && (
            <Banner tone="good" title="Valid">Server validation passed{v.summary ? ` · ${v.summary}` : ''}. {base.status === 'draft' ? (dirty ? 'Save the draft, then activate.' : 'Activate when ready.') : dirty ? 'Save to apply.' : ''}</Banner>
          )}
          <FlowCanvas model={model} />
        </div>
        {sel && (
          <div
            className={cn('overflow-auto border-l border-border bg-card', overlay && 'absolute bottom-0 right-0 top-0 z-20 w-[360px] max-w-[90%] shadow-[-12px_0_32px_rgba(0,0,0,0.35)]')}
            data-testid="flow-inspector"
          >
            <div className="sticky top-0 z-10 flex h-9 items-center gap-1 border-b border-border bg-card px-3">
              <span className="flex-1 font-mono text-[10.5px] text-muted-foreground">{sel}</span>
              {s && !ro && (
                <>
                  <IconBtn label="Move up" onClick={() => move(s.id, -1)}><ArrowUp strokeWidth={1.5} /></IconBtn>
                  <IconBtn label="Move down" onClick={() => move(s.id, 1)}><ArrowDown strokeWidth={1.5} /></IconBtn>
                  <IconBtn label="Duplicate step" onClick={() => dup(s.id)}><Copy strokeWidth={1.5} /></IconBtn>
                  <IconBtn label="Delete step" onClick={() => del(s.id)} danger><Trash2 strokeWidth={1.5} /></IconBtn>
                </>
              )}
              <IconBtn label="Close" onClick={() => { setSel0(null); setPalAnchor(null); }}><X strokeWidth={1.5} /></IconBtn>
            </div>
            <FlowInspector sel={sel} s={s} doc={ed.doc} trigger={ed.trigger} setTrigger={(t, key) => apply({ trigger: t }, key)} upd={updModule} ro={ro} ctx={ctx} nextRun={flow.next_run_at} />
            {T && results[sel] && (
              <div className="flex flex-col gap-2 border-t border-border px-4 py-3.5">
                <div className="flex items-center gap-2"><H className="flex-1">Test output · {shortId(T.id)}</H><Res r={results[sel]} /></div>
                {results[sel].out && <pre className="whitespace-pre-wrap rounded-md border border-border bg-background px-2.5 py-2 font-mono text-[10.5px] leading-[1.6] text-fg-2">{results[sel].out}</pre>}
              </div>
            )}
            {T && !results[sel] && sel !== 'trigger' && (
              <div className="border-t border-border px-4 py-3.5 font-mono text-[10.5px] text-muted-foreground">Not run in test {shortId(T.id)}: branch not taken.</div>
            )}
          </div>
        )}
      </div>
      {runDialog && (
        <RunFlowDialog
          open
          onOpenChange={(o) => !o && setRunDialog(null)}
          flow={flow}
          tenant={gate.tenant}
          dryRun={runDialog === 'dry'}
          onQueued={runDialog === 'dry' ? (r) => setTestId(r.id) : undefined}
        />
      )}
      <ConfirmDialog
        open={confirmLiveSave}
        onOpenChange={setConfirmLiveSave}
        variant="warning"
        title={`Save changes to the live flow ${base.name}?`}
        description="This flow is live. Runs triggered after saving use the new definition. Runs already in flight keep the version they started with."
        confirmLabel="Save live flow"
        onConfirm={() => save.mutate()}
      />
      <ConfirmDialog
        open={statusTarget !== null}
        onOpenChange={(o) => !o && setStatusTarget(null)}
        variant={statusTarget === 'live' ? 'warning' : 'default'}
        title={statusTarget === 'live' ? `Activate ${base.name}?` : statusTarget === 'archived' ? `Archive ${base.name}?` : `Restore ${base.name} as draft?`}
        description={
          statusTarget === 'live'
            ? 'Its trigger starts firing real runs. Actions still respect approval policy.'
            : statusTarget === 'archived'
              ? 'Its trigger stops firing. Runs already queued continue.'
              : 'The flow returns to draft and does not fire until activated.'
        }
        confirmLabel={statusTarget === 'live' ? 'Activate' : statusTarget === 'archived' ? 'Archive' : 'Restore'}
        onConfirm={() => statusTarget && setStatus.mutate(statusTarget)}
      />
    </div>
  );
}

function IconBtn({ label, onClick, children, danger }: { label: string; onClick: () => void; children: React.ReactElement; danger?: boolean }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className={cn('flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-background [&>svg]:h-3.5 [&>svg]:w-3.5', danger ? 'hover:text-destructive' : 'hover:text-foreground')}
    >
      {children}
    </button>
  );
}
