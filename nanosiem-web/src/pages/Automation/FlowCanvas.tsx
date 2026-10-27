// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — the flow editor's vertical spine (port of soar3-flow.jsx Blk3,
 * Gap3, Wire3, Branch3, Cols, Stk and the canvas in FlowEditor3).
 *
 * Generalized from the mock's flat step list to the stored module tree: the
 * first top-level `branchone` renders as the mock's branch chip with then /
 * else columns; loops render as dashed containers; nested branches render as
 * containers with one lane per arm.
 */
import { Fragment, useState, type DragEvent, type KeyboardEvent, type ReactElement, type ReactNode } from 'react';
import { Plus } from 'lucide-react';
import type { SoarFlowTrigger } from '@/lib/api/soar';
import { cn } from '@/lib/utils';
import type { Ctx, DragItem, DropAt, FlowDoc, RawModule } from './flow-editor-model';
import { ROOT, actionOf, childLists, retryAttempts, staticNumber, suspendSecs, transform, typeOf } from './flow-editor-model';
import type { TestResult } from './flow-test-results';
import { asEffect, triggerLabel } from './soar-model';
import { bindingParts, conditionParts, scopeFields } from './soar-fields';
import { BoundText, FieldName } from './flow-easy';

export interface Dnd {
  drag: DragItem | null;
  ro: boolean;
  start: (d: DragItem) => void;
  end: () => void;
  ok: (at: DropAt) => boolean;
  drop: (at: DropAt) => void;
  dropTrigger: () => void;
}

export interface CanvasModel {
  doc: FlowDoc;
  trigger: SoarFlowTrigger;
  ctx: Ctx;
  sel: string | null;
  select: (id: string) => void;
  errors: Map<string, string[]>;
  results: Record<string, TestResult>;
  /** Branch taken per branchone in the overlaid test; undefined when no test. */
  taken?: Map<string, number | 'default' | null>;
  dnd: Dnd;
  ro: boolean;
  compact: boolean;
  stack: boolean;
  /** NAN-4661: wraps an "add to …" button so it opens the block picker for `at`. */
  addPicker: (at: DropAt, label: string, button: ReactElement) => ReactNode;
  onBlockKey: (id: string, e: KeyboardEvent) => void;
  /** NAN-4653: steps pivt just changed or added (highlighted for a few seconds). */
  glow?: ReadonlySet<string>;
}

const KIND: Record<string, [string, string]> = {
  trigger: ['TRIGGER', 'text-muted-foreground'],
  action: ['ACTION', 'text-primary'],
  approval: ['GATE', 'text-warn'],
  forloopflow: ['LOOP', 'text-fg-2'],
  identity: ['PASS', 'text-muted-foreground'],
  search: ['SEARCH', 'text-primary'],
  'notify.email': ['EMAIL', 'text-warn'],
  judge: ['JUDGE', 'text-ai'],
  branchone: ['BRANCH', 'text-fg-2'],
  branchall: ['BRANCH', 'text-fg-2'],
};

export function EffTag({ e, className }: { e: string | null | undefined; className?: string }) {
  if (!e) return null;
  if (e === 'ai') return <span className={cn('shrink-0 font-mono text-[10.5px] text-ai', className)}>AI</span>;
  return <span className={cn('shrink-0 font-mono text-[10.5px]', e === 'read' ? 'text-muted-foreground' : e === 'write' ? 'text-warn' : 'text-destructive', className)}>{e}</span>;
}

export function Res({ r }: { r?: TestResult }) {
  if (!r) return null;
  return (
    <span className={cn('whitespace-nowrap font-mono text-[10.5px]', r.st === 'ok' ? 'text-good' : r.st === 'fail' ? 'text-destructive' : r.st === 'wait' ? 'text-warn' : 'text-muted-foreground')}>
      {r.st === 'ok' ? '✓ ' : r.st === 'fail' ? '✕ ' : '– '}
      {r.m}
    </span>
  );
}

export function Wire({ h = 14, label }: { h?: number; label?: string | null }) {
  return (
    <div className="relative flex shrink-0 justify-center" style={{ height: label ? 26 : h }}>
      <span className="h-full w-px bg-border-2" />
      {label && <span className="absolute left-[calc(50%+8px)] top-1/2 -translate-y-1/2 whitespace-nowrap font-mono text-[10px] text-warn">{label}</span>}
    </div>
  );
}

/** Drop zone between blocks; idle content when nothing is being dragged. */
export function Gap({ dnd, at, idle }: { dnd: Dnd; at: DropAt; idle?: ReactNode }) {
  const [over, setOver] = useState(false);
  if (!dnd.drag || !dnd.ok(at)) return <>{idle === undefined ? <Wire /> : idle}</>;
  return (
    <div
      data-testid="drop-gap"
      data-drop={`${at.ref.owner ?? 'root'}:${String(at.ref.slot)}:${at.before ?? 'end'}`}
      onDragOver={(e) => {
        e.preventDefault();
        if (e.dataTransfer) e.dataTransfer.dropEffect = dnd.drag?.kind === 'move' ? 'move' : 'copy';
        if (!over) setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        dnd.drop(at);
      }}
      className="relative flex shrink-0 items-center py-1.5"
    >
      <span className="pointer-events-none absolute inset-y-0 left-1/2 w-px bg-border-2" />
      <span
        className={cn(
          'pointer-events-none relative flex w-full items-center justify-center rounded-md border border-dashed font-mono text-[10px] transition-all',
          over ? 'h-9 border-primary bg-background text-primary' : 'h-4 border-border-2 bg-card text-transparent',
        )}
      >
        drop here
      </span>
    </div>
  );
}

export function dragProps(dnd: Dnd, item: DragItem) {
  if (dnd.ro) return {};
  return {
    draggable: true,
    onDragStart: (e: DragEvent) => {
      e.dataTransfer?.setData('text/plain', item.kind === 'move' ? item.id : item.label);
      if (e.dataTransfer) e.dataTransfer.effectAllowed = item.kind === 'move' ? 'move' : 'copy';
      // Defer so the browser captures the drag image before the canvas re-renders.
      setTimeout(() => dnd.start(item), 0);
    },
    onDragEnd: () => dnd.end(),
  };
}

function minutes(secs: number | null): string {
  if (secs === null) return '—';
  const m = secs / 60;
  return Number.isInteger(m) ? String(m) : m.toFixed(1);
}

function triggerTitle(t: SoarFlowTrigger): [string, string] {
  switch (t.on) {
    case 'alert': return ['Alert committed', t.match ? `match ${t.match}` : 'any committed alert'];
    case 'case': return ['Case event', t.match ? `match ${t.match}` : 'any case event'];
    case 'case.triage_verdict': return ['Case triage verdict', t.match ? `match ${t.match}` : 'any verdict'];
    case 'schedule': return ['Schedule', t.cron ? `cron ${t.cron} · UTC` : 'no schedule set'];
    case 'manual': return ['Manual', 'on demand'];
    default: return [triggerLabel(t), ''];
  }
}

function describe(m: RawModule, ctx: Ctx, model: CanvasModel): { title: string; sub: ReactNode } {
  const v = m.value;
  const t = typeOf(m);
  if (t === 'action') {
    const found = actionOf(m, ctx.index);
    const fx = asEffect(found?.action.effect);
    const pack = String(v.pack ?? '');
    const action = String(v.action ?? '');
    return {
      title: found ? `${found.action.display_name} · ${found.pack.vendor}` : `${pack}.${action}`,
      sub: (
        <>
          {pack}.{action} · <EffTag e={fx ?? 'write'} />
          {found?.action.rollback && <span> · ↺ undo</span>}
          {fx === 'write' && !found?.action.approval_forced && <span> · {v.approval === 'auto' ? 'auto-approved' : 'needs approval'}</span>}
          {(fx === 'destructive' || (fx === 'write' && found?.action.approval_forced)) && <span> · always approved</span>}
          {fx === 'read' && v.approval === 'required' && <span> · needs approval</span>}
          {retryAttempts(m) > 0 && <span> · retry ×{retryAttempts(m)}</span>}
        </>
      ),
    };
  }
  if (t === 'approval') {
    const opts = Array.isArray(v.options) ? (v.options as string[]) : [];
    return { title: String(v.prompt || m.summary || 'Approval'), sub: <>soar:approve · {minutes(suspendSecs(m) ?? 86_400)}m expiry{opts.length ? ` · ${opts.join(' / ')}` : ''}</> };
  }
  if (t === 'forloopflow') {
    const it = transform(v.iterator);
    const p = staticNumber(v.parallelism);
    return { title: `For each in ${it?.type === 'expr' ? it.expr || '…' : JSON.stringify(it?.value ?? '…')}`, sub: <>≤100 items{v.parallel ? ` · parallel ×${p ?? 1}` : ' · sequential'}{v.skip_failures ? ' · skip failures' : ''}</> };
  }
  if (t === 'search') {
    // NAN-4586: bindings read as "Alert → Host" chips, like the easy editor.
    const parts = bindingParts(String(v.query || '…'), scopeFields(model.doc, model.trigger.on, m.id, ctx.index));
    return { title: m.summary || 'nPL search', sub: <><BoundText parts={parts} /> · {String(v.window ?? '')} · ≤{String(v.limit ?? '')} rows</> };
  }
  if (t === 'notify.email') return { title: `Email ${String(v.to || '…')}`, sub: <>{String(v.subject || 'no subject')} · <EffTag e="write" /></> };
  if (t === 'judge') {
    // NAN-4660: the question is the title (trimmed for the aria label too); the labels are the sub-line.
    const q = String(v.question || '').trim().replace(/\s+/g, ' ');
    const labels = Array.isArray(v.labels) ? (v.labels as unknown[]).filter((x): x is string => typeof x === 'string') : [];
    return { title: q ? (q.length > 90 ? `${q.slice(0, 89)}…` : q) : m.summary || 'AI judge', sub: <>{labels.length ? labels.join(' / ') : 'no labels'}</> };
  }
  if (t === 'branchone' || t === 'branchall') return { title: m.summary || 'Branch', sub: <>{childLists(m).length} lanes{t === 'branchall' ? ' · all run' : ' · first match'}</> };
  return { title: (m.summary || 'Pass-through').split(' · ')[0], sub: <>no-op · passes through</> };
}

export function Block({ m, model, trigger }: { m?: RawModule; model: CanvasModel; trigger?: boolean }) {
  const { dnd, compact, sel } = model;
  const kind = trigger ? 'trigger' : typeOf(m!);
  const [kl, kc] = KIND[kind] ?? ['STEP', 'text-muted-foreground'];
  const id = trigger ? 'trigger' : m!.id;
  const errs = model.errors.get(id) ?? [];
  const on = sel === id;
  const res = model.results[id];
  let title: string;
  let sub: ReactNode;
  if (trigger) [title, sub] = triggerTitle(model.trigger);
  else ({ title, sub } = describe(m!, model.ctx, model));
  const triggerDrop = trigger && dnd.drag?.kind === 'trigger';
  return (
    <button
      type="button"
      data-testid="flow-step"
      data-step-id={id}
      data-pivt-changed={model.glow?.has(id) || undefined}
      aria-pressed={on}
      aria-label={`${kl} ${title}`}
      onClick={() => model.select(id)}
      onKeyDown={(e) => !trigger && model.onBlockKey(id, e)}
      {...(!trigger ? dragProps(dnd, { kind: 'move', id }) : {})}
      {...(triggerDrop
        ? {
            onDragOver: (e: DragEvent) => {
              e.preventDefault();
              if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
            },
            onDrop: (e: DragEvent) => {
              e.preventDefault();
              dnd.dropTrigger();
            },
          }
        : {})}
      className={cn(
        'grid w-full items-center rounded-md border bg-card px-3 py-2.5 text-left',
        !trigger && !dnd.ro && 'cursor-grab active:cursor-grabbing',
        dnd.drag?.kind === 'move' && dnd.drag.id === id && 'opacity-40',
        triggerDrop && '!border-dashed !border-primary',
        compact ? 'grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-0.5' : 'grid-cols-[64px_minmax(0,1fr)_auto] gap-3',
        on ? 'border-foreground' : errs.length ? 'border-destructive/60' : kind === 'approval' ? 'border-dashed border-warning/70 hover:border-warning' : 'border-border hover:border-border-2',
        model.glow?.has(id) && !on && '!border-primary bg-primary/5 transition-colors duration-700',
      )}
    >
      <span className={cn('font-mono text-[10.5px] tracking-[0.06em]', kc)}>{kl}</span>
      {compact && <span className="justify-self-end"><Res r={res} /></span>}
      <span className={cn('min-w-0', compact && 'col-span-2')}>
        <span className="block truncate text-[12.5px] text-foreground">{title}</span>
        <span className="mt-0.5 block truncate font-mono text-[10.5px] text-muted-foreground">
          {errs.length ? <span className="text-destructive" data-testid="step-error">{errs[0]}</span> : sub}
        </span>
      </span>
      {!compact && <Res r={res} />}
    </button>
  );
}

/** One container's modules with drop gaps (mock Branch3 without the footer). */
function Seq({ list, ref: cref, model, first }: { list: RawModule[]; ref: DropAt['ref']; model: CanvasModel; first?: 'wire' | 'none' }) {
  const { dnd } = model;
  return (
    <>
      {list.map((m, i) => {
        const lead = i === 0 && first !== 'wire'
          ? <Gap dnd={dnd} at={{ ref: cref, before: m.id }} idle={null} />
          : <Gap dnd={dnd} at={{ ref: cref, before: m.id }} idle={<Wire label={typeOf(m) === 'approval' ? '‖ pauses until approved' : null} />} />;
        return <Fragment key={m.id}>{lead}<Node m={m} model={model} /></Fragment>;
      })}
    </>
  );
}

function Node({ m, model }: { m: RawModule; model: CanvasModel }) {
  const t = typeOf(m);
  const kids = childLists(m);
  if (kids.length === 0) return <Block m={m} model={model} />;
  return (
    <div className={cn('flex flex-col rounded-lg border border-dashed p-2', model.sel === m.id ? 'border-foreground' : 'border-border-2')} data-testid={t === 'forloopflow' ? 'flow-loop' : 'flow-branch-box'}>
      <Block m={m} model={model} />
      {kids.map((c) => (
        <Fragment key={String(c.ref.slot)}>
          {t !== 'forloopflow' && <div className="mt-2 px-1 font-mono text-[10px] text-muted-foreground">{c.label}</div>}
          <Seq list={c.list} ref={c.ref} model={model} first="wire" />
          <Gap dnd={model.dnd} at={{ ref: c.ref, before: null }} idle={null} />
        </Fragment>
      ))}
    </div>
  );
}

/** A branch lane with "add to …" and the end marker (mock Branch3). */
function Lane({ list, cref, label, model, dim }: { list: RawModule[]; cref: DropAt['ref']; label: string; model: CanvasModel; dim?: boolean }) {
  return (
    <div className={cn('flex flex-col transition-opacity', dim && 'opacity-40')} data-testid={`lane-${label}`}>
      <Seq list={list} ref={cref} model={model} />
      <Gap dnd={model.dnd} at={{ ref: cref, before: null }} />
      {!model.ro && model.addPicker({ ref: cref, before: null }, `Add to ${label}`, (
        <button
          type="button"
          className="flex h-9 items-center justify-center gap-1.5 rounded-md border border-dashed border-border-2 text-[11.5px] text-muted-foreground hover:border-fg-4 hover:text-foreground data-[state=open]:border-fg-4 data-[state=open]:text-foreground"
        >
          <Plus className="h-3 w-3" strokeWidth={1.5} />
          add to {label}
        </button>
      ))}
      <Wire />
      <div className="flex items-center justify-center gap-2">
        <span className="h-2 w-2 rounded-full bg-muted-foreground" />
        <span className="font-mono text-[10px] text-muted-foreground">end · {label}</span>
      </div>
    </div>
  );
}

const Cols = ({ l, r, className }: { l: ReactNode; r?: ReactNode; className?: string }) => (
  <div className={cn('flex gap-10', className)}>
    <div className="min-w-[240px] max-w-[520px] flex-[1.5_1_0]">{l}</div>
    <div className="min-w-[200px] max-w-[360px] flex-[1_1_0]">{r}</div>
  </div>
);

export function FlowCanvas({ model }: { model: CanvasModel }) {
  const { doc, dnd, stack, taken } = model;
  const root = doc.value.modules;
  const ci = root.findIndex((m) => typeOf(m) === 'branchone');
  const cond = ci >= 0 ? root[ci] : null;
  const pre = ci >= 0 ? root.slice(0, ci) : root;
  const post = ci >= 0 ? root.slice(ci + 1) : [];
  const lanes = cond ? childLists(cond) : [];
  const taken0 = cond && taken ? taken.get(cond.id) : undefined;
  const tested = taken !== undefined && taken0 !== undefined;
  const laneLabel = (slot: number | 'default', label: string) => (slot === 'default' ? 'else' : slot === 0 ? 'then' : label);
  const notTaken = (slot: number | 'default') => tested && taken0 !== slot;
  const condExpr = cond ? String(((cond.value.branches as Array<Record<string, unknown>> | undefined)?.[0]?.expr) ?? '') : '';
  // NAN-4586: the same sentence the inspector's easy mode shows.
  const condSentence = cond && condExpr ? conditionParts(condExpr, scopeFields(doc, model.trigger.on, cond.id, model.ctx.index)) : null;

  const head = (
    <div className="flex flex-col">
      <Block trigger model={model} />
      <Seq list={pre} ref={ROOT} model={model} first="wire" />
      <Gap dnd={dnd} at={{ ref: ROOT, before: cond ? cond.id : null }} idle={null} />
      {!cond && !model.ro && (
        <>
          <Wire />
          {model.addPicker({ ref: ROOT, before: null }, 'Add step', (
            <button
              type="button"
              className="flex h-9 items-center justify-center gap-1.5 rounded-md border border-dashed border-border-2 text-[11.5px] text-muted-foreground hover:border-fg-4 hover:text-foreground data-[state=open]:border-fg-4 data-[state=open]:text-foreground"
            >
              <Plus className="h-3 w-3" strokeWidth={1.5} />
              add step
            </button>
          ))}
        </>
      )}
      {!cond && (
        <>
          <Wire />
          <div className="flex items-center justify-center gap-2">
            <span className="h-2 w-2 rounded-full bg-muted-foreground" />
            <span className="font-mono text-[10px] text-muted-foreground">end</span>
          </div>
        </>
      )}
    </div>
  );
  const chip = cond && (
    <>
      <Wire />
      <div className="flex justify-center">
        <button
          type="button"
          data-testid="flow-step"
          data-step-id={cond.id}
          data-pivt-changed={model.glow?.has(cond.id) || undefined}
          onClick={() => model.select(cond.id)}
          onKeyDown={(e) => model.onBlockKey(cond.id, e)}
          className={cn(
            'flex h-7 max-w-full items-center gap-2 whitespace-nowrap rounded-full border bg-card px-3 font-mono text-[11px]',
            model.sel === cond.id ? 'border-foreground text-foreground' : (model.errors.get(cond.id)?.length ? 'border-destructive/60 text-destructive' : 'border-border-2 text-fg-2 hover:text-foreground'),
            model.glow?.has(cond.id) && model.sel !== cond.id && '!border-primary bg-primary/5',
          )}
        >
          <span className="text-muted-foreground">branch</span>
          {condSentence
            ? (
              <span className="truncate font-sans text-[11.5px]" title={condExpr} data-testid="branch-sentence">
                When <FieldName label={condSentence.label} path={condSentence.path} /> {condSentence.op}{condSentence.values.length ? ` ${condSentence.values.join(', ')}` : ''}
              </span>
            )
            : <span className="truncate">{condExpr || 'set a condition'}</span>}
          <Res r={model.results[cond.id]} />
        </button>
      </div>
    </>
  );
  const postBlock = post.length > 0 && (
    <Cols
      l={
        <div className="flex flex-col">
          <Wire label="joins" />
          <Seq list={post} ref={ROOT} model={model} first="wire" />
          <Gap dnd={dnd} at={{ ref: ROOT, before: null }} idle={null} />
        </div>
      }
    />
  );

  return (
    <div className="overflow-x-auto rounded-[10px] border border-border px-4 py-6" data-testid="flow-canvas">
      <div className="mx-auto w-fit max-w-full">
        {stack ? (
          <div className="mx-auto flex w-full max-w-[520px] flex-col">
            {head}
            {cond && (
              <>
                {chip}
                {lanes.map((ln, i) => {
                  const lab = laneLabel(ln.ref.slot as number | 'default', ln.label);
                  return (
                    <Fragment key={String(ln.ref.slot)}>
                      {i === 0 ? (
                        <Wire label={notTaken(ln.ref.slot as number | 'default') ? `${lab} · not taken` : lab} />
                      ) : (
                        <div className="mb-2 mt-6 flex items-center gap-2">
                          <span className="h-px flex-1 bg-border-2" />
                          <span className={cn('whitespace-nowrap font-mono text-[10.5px]', tested ? (notTaken(ln.ref.slot as number | 'default') ? 'text-fg-4' : 'text-good') : 'text-fg-2')}>
                            {lab}{notTaken(ln.ref.slot as number | 'default') ? ' · not taken' : ''}
                          </span>
                          <span className="h-px flex-1 bg-border-2" />
                        </div>
                      )}
                      <Lane list={ln.list} cref={ln.ref} label={lab} model={model} dim={notTaken(ln.ref.slot as number | 'default')} />
                    </Fragment>
                  );
                })}
                {post.length > 0 && (
                  <>
                    <Wire label="joins" />
                    <Seq list={post} ref={ROOT} model={model} first="wire" />
                    <Gap dnd={dnd} at={{ ref: ROOT, before: null }} idle={null} />
                  </>
                )}
              </>
            )}
          </div>
        ) : (
          <>
            <Cols l={head} />
            {cond && (
              <>
                <Cols l={chip} />
                <div className="flex gap-10">
                  {lanes.map((ln, i) => {
                    const slot = ln.ref.slot as number | 'default';
                    const lab = laneLabel(slot, ln.label);
                    return (
                      <div key={String(slot)} className={cn(i === 0 ? 'min-w-[240px] max-w-[520px] flex-[1.5_1_0]' : 'min-w-[200px] max-w-[360px] flex-[1_1_0]')}>
                        <div className="relative h-[34px]">
                          {i === 0 ? (
                            <>
                              <span className="absolute bottom-0 left-1/2 top-0 w-px bg-border-2" />
                              <span className="absolute -right-10 left-1/2 top-[10px] h-px bg-border-2" />
                            </>
                          ) : (
                            <>
                              <span className={cn('absolute top-[10px] h-px bg-border-2', i === lanes.length - 1 ? 'left-0 right-1/2' : '-right-10 left-0')} />
                              <span className="absolute bottom-0 left-1/2 top-[10px] w-px bg-border-2" />
                            </>
                          )}
                          <span
                            className={cn('absolute top-[14px] whitespace-nowrap font-mono text-[10.5px]', tested ? (notTaken(slot) ? 'text-fg-4' : 'text-good') : 'text-fg-2')}
                            style={{ left: 'calc(50% + 8px)' }}
                          >
                            {lab}{notTaken(slot) ? ' · not taken' : ''}
                          </span>
                        </div>
                        <Lane list={ln.list} cref={ln.ref} label={lab} model={model} dim={notTaken(slot)} />
                      </div>
                    );
                  })}
                </div>
                {postBlock}
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}
