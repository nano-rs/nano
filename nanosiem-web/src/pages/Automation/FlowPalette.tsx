// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4546 — block palette (port of soar3-flow.jsx Palette3 / PalRow3 / PalGrp3). */
import { useState, type ReactNode } from 'react';
import type { SoarCatalog, SoarConnection } from '@/lib/api/soar';
import { cn } from '@/lib/utils';
import type { DragItem, NewSpec } from './flow-editor-model';
import type { Dnd } from './FlowCanvas';
import { EffTag, dragProps } from './FlowCanvas';
import { Note } from './soar-kit';
import { asEffect } from './soar-model';

export const TRIGGERS: Array<[string, string]> = [
  ['Alert committed', 'alert'],
  ['Case event', 'case'],
  ['Case triage verdict', 'case.triage_verdict'],
  ['Schedule', 'schedule'],
  ['Manual', 'manual'],
];

function Row({ children, tag, onClick, ro, drag, dnd, off }: { children: ReactNode; tag?: ReactNode; onClick: () => void; ro: boolean; drag: DragItem; dnd: Dnd; off?: string | null }) {
  return (
    <button
      type="button"
      disabled={ro || !!off}
      onClick={onClick}
      {...(off ? {} : dragProps(dnd, drag))}
      title={off || undefined}
      data-testid="palette-row"
      className={cn('flex h-7 w-full items-center gap-2 rounded border border-border bg-card px-2 text-left hover:border-border-2 disabled:opacity-60', !ro && !off && 'cursor-grab active:cursor-grabbing')}
    >
      {!ro && !off && <span className="shrink-0 text-[10px] leading-none tracking-[-1px] text-fg-4">⋮⋮</span>}
      <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-foreground">{children}</span>
      {tag}
    </button>
  );
}
function Group({ t, children }: { t: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="px-0.5 pt-2 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">{t}</div>
      {children}
    </div>
  );
}

/** One addable block, shared by the palette and the canvas "add to …" picker (NAN-4661). */
export interface BlockEntry {
  key: string;
  group: 'Logic' | 'Pack actions';
  label: string;
  spec: NewSpec;
  tag?: ReactNode;
  /** Pack name for pack actions. */
  pack?: string;
  /** Why the block cannot be added; null when it can. */
  off: string | null;
}

/** Logic blocks, then actions of installed, enabled, connected packs. */
export function blockEntries(catalog: SoarCatalog | undefined, connections: SoarConnection[], hasCondition: boolean, judgeOff: string | null = null): BlockEntry[] {
  const allLogic: Array<{ label: string; spec: NewSpec; tag?: ReactNode }> = [
    { label: 'Condition', spec: { block: 'condition' }, tag: <span className="shrink-0 whitespace-nowrap font-mono text-[10.5px] text-muted-foreground">1 per flow</span> },
    { label: 'Loop', spec: { block: 'loop' } },
    { label: 'Approval gate', spec: { block: 'approval' }, tag: <span className="shrink-0 whitespace-nowrap font-mono text-[10.5px] text-warn">pauses</span> },
    { label: 'Pass-through', spec: { block: 'pass' } },
    { label: 'nPL search', spec: { block: 'search' }, tag: <EffTag e="read" /> },
    { label: 'Judge', spec: { block: 'judge' }, tag: <EffTag e="ai" /> },
    { label: 'Email', spec: { block: 'email' }, tag: <EffTag e="write" /> },
  ];
  const logic: BlockEntry[] = allLogic.map((x) => ({
    key: x.label,
    group: 'Logic',
    label: x.label,
    spec: x.spec,
    tag: x.tag,
    off: x.spec.block === 'condition' && hasCondition ? 'One branch per flow in this version' : x.spec.block === 'judge' ? judgeOff : null,
  }));
  const acts: BlockEntry[] = (catalog?.packs ?? [])
    .filter((p) => p.installed && p.enabled && !p.withdrawn && connections.some((c) => c.pack_name === p.name))
    .flatMap((p) => p.actions.map((a): BlockEntry => {
      const k = `${p.name}.${a.name}`;
      return { key: k, group: 'Pack actions', label: k, spec: { block: 'action', pack: p.name, action: a.name }, tag: <EffTag e={asEffect(a.effect) ?? 'write'} />, pack: p.name, off: null };
    }));
  return [...logic, ...acts];
}

export function FlowPalette({ ro, dnd, catalog, connections, hasCondition, judgeOff = null, onAdd, onTrigger }: {
  ro: boolean;
  dnd: Dnd;
  catalog: SoarCatalog | undefined;
  connections: SoarConnection[];
  hasCondition: boolean;
  /** NAN-4660: why the AI judge cannot be added (no meloD / melod:summarize); null when it can. */
  judgeOff?: string | null;
  onAdd: (spec: NewSpec) => void;
  onTrigger: (on: string) => void;
}) {
  const [q, setQ] = useState('');
  const m = (t: string) => t.toLowerCase().includes(q.toLowerCase());
  const trigs = TRIGGERS.filter(([l]) => m(l));
  const entries = blockEntries(catalog, connections, hasCondition, judgeOff).filter((x) => m(x.label));
  const logic = entries.filter((x) => x.group === 'Logic');
  const acts = entries.filter((x) => x.group === 'Pack actions');
  return (
    <div className="flex min-h-0 flex-col border-r border-border" data-testid="flow-palette">
      <div className="flex flex-col gap-2 border-b border-border p-3">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search blocks"
          aria-label="Search blocks"
          className="h-8 w-full rounded-md border border-border bg-background px-2.5 text-[12px] text-foreground outline-none placeholder:text-muted-foreground focus:border-fg-4"
        />
        {!ro && <div className="font-mono text-[10px] text-muted-foreground">drag onto the flow · click adds after the selected step</div>}
      </div>
      <div className="flex min-h-0 flex-1 flex-col gap-1 overflow-auto px-3 pb-3">
        {trigs.length > 0 && (
          <Group t="Triggers · replaces current">
            {trigs.map(([l, on]) => <Row key={on} ro={ro} dnd={dnd} drag={{ kind: 'trigger', on, label: l }} onClick={() => onTrigger(on)}>{l}</Row>)}
          </Group>
        )}
        {logic.length > 0 && (
          <Group t="Logic">
            {logic.map((x) => (
              <Row key={x.key} ro={ro} dnd={dnd} off={x.off} drag={{ kind: 'new', spec: x.spec, label: x.label }} onClick={() => onAdd(x.spec)} tag={x.tag}>
                {x.label}
              </Row>
            ))}
          </Group>
        )}
        {acts.length > 0 && (
          <Group t={`Pack actions · ${new Set(acts.map((x) => x.pack)).size} packs`}>
            {acts.map((x) => (
              <Row key={x.key} ro={ro} dnd={dnd} drag={{ kind: 'new', spec: x.spec, label: x.label }} tag={x.tag} onClick={() => onAdd(x.spec)}>
                {x.label}
              </Row>
            ))}
          </Group>
        )}
        {!trigs.length && !acts.length && !logic.length && <div className="px-1 pt-3 text-[11.5px] text-muted-foreground">No blocks match.</div>}
      </div>
      <Note className="m-3 mt-0">Allowed steps only. No JS, Python, script upload or subflow-by-path.</Note>
    </div>
  );
}
