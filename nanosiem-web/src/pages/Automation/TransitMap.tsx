// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4540 — read-only "transit map" of a flow definition: each module is a
 * station on one line; branches and loops fork into parallel sub-lines.
 * Built from the stored definition only (Windmill subset).
 */
import { cn } from '@/lib/utils';
import type { FlowNode, IndexedAction, LineStop } from './soar-model';
import { asEffect, flowLine, lookupAction } from './soar-model';
import { EffectTag } from './soar-kit';

const KIND_LABEL: Record<FlowNode['kind'], string> = {
  action: 'action',
  approval: 'approval gate',
  loop: 'for each',
  branchone: 'branch · first match',
  branchall: 'branch · all',
  identity: 'pass-through',
  search: 'nPL search',
  judge: 'pivt judge',
  email: 'email',
  unknown: 'unknown step',
};

function Station({ stop }: { stop: LineStop }) {
  return (
    <span
      aria-hidden
      className={cn(
        'relative z-10 mt-1 inline-block h-3 w-3 shrink-0 rounded-full border-[1.5px] bg-background',
        stop === 'read' && 'border-muted-foreground',
        stop === 'write' && 'border-warning bg-warning',
        stop === 'destructive' && 'border-destructive bg-destructive',
        stop === 'gate' && 'rounded-[2px] border-warning',
        (stop === 'fork' || stop === 'loop') && 'rounded-[2px] border-foreground',
        (stop === 'search' || stop === 'judge' || stop === 'email' || stop === 'pass') && 'border-primary',
      )}
    />
  );
}

function stopFor(node: FlowNode, index: Map<string, IndexedAction>): LineStop {
  return flowLine([node], index)[0];
}

function NodeDetail({ node, index }: { node: FlowNode; index: Map<string, IndexedAction> }) {
  const found = lookupAction(index, node.pack, node.action);
  const flags = [
    node.approval && node.approval !== 'default' ? `approval ${node.approval}` : null,
    node.retries ? `retry ×${node.retries}` : null,
    node.timeoutSecs ? `timeout ${node.timeoutSecs}s` : null,
    node.continueOnError ? 'continue on error' : null,
    node.parallel ? 'parallel' : null,
  ].filter(Boolean);
  return (
    <div className="min-w-0 flex-1 pb-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[12px] font-medium text-foreground">
          {node.kind === 'action' ? found?.action.display_name ?? node.action ?? node.id : node.summary || KIND_LABEL[node.kind]}
        </span>
        {node.kind === 'action' && <EffectTag effect={asEffect(found?.action.effect)} />}
        <span className="font-mono text-[10.5px] text-muted-foreground">{node.id}</span>
      </div>
      <div className="mt-0.5 flex flex-wrap gap-x-2 font-mono text-[10.5px] text-muted-foreground">
        <span>{KIND_LABEL[node.kind]}</span>
        {node.kind === 'action' && <span>{node.pack}{found ? '' : ' · pack not installed'}</span>}
        {flags.map((f) => <span key={f}>{f}</span>)}
      </div>
      {node.kind === 'action' && node.summary && <div className="mt-0.5 text-[11.5px] text-fg-2">{node.summary}</div>}
      {node.prompt && <div className="mt-0.5 text-[11.5px] text-fg-2">{node.prompt}</div>}
      {node.options && node.options.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-1">
          {node.options.map((o) => (
            <span key={o} className="rounded-[3px] border border-border px-1.5 font-mono text-[10.5px] text-fg-2">{o}</span>
          ))}
        </div>
      )}
      {node.query && (
        <code className="mt-1 block truncate rounded-[3px] border border-border bg-background px-1.5 py-0.5 font-mono text-[10.5px] text-fg-2" title={node.query}>
          {node.query}{node.window ? ` · ${node.window}` : ''}
        </code>
      )}
      {node.question && <div className="mt-0.5 text-[11.5px] text-fg-2">{node.question}</div>}
      {node.skipIf && <div className="mt-0.5 font-mono text-[10.5px] text-muted-foreground">skip if {node.skipIf}</div>}
    </div>
  );
}

export function TransitLine({ nodes, index, depth = 0 }: { nodes: FlowNode[]; index: Map<string, IndexedAction>; depth?: number }) {
  if (nodes.length === 0) {
    return <div className="py-1 pl-5 font-mono text-[10.5px] text-muted-foreground">no steps</div>;
  }
  return (
    <ol className="relative" data-testid={depth === 0 ? 'transit-map' : undefined}>
      {nodes.map((node, i) => (
        <li key={`${node.id}-${i}`} className="relative flex gap-2.5">
          {i < nodes.length - 1 && <span aria-hidden className="absolute left-[5px] top-4 h-[calc(100%-4px)] w-px bg-border-2" />}
          <Station stop={stopFor(node, index)} />
          <div className="min-w-0 flex-1">
            <NodeDetail node={node} index={index} />
            {node.branches.length > 0 && (
              <div className="mb-3 grid gap-2" style={{ gridTemplateColumns: `repeat(${Math.min(node.branches.length, 3)}, minmax(0, 1fr))` }}>
                {node.branches.map((b, j) => (
                  <div key={j} className="min-w-0 rounded-md border border-border px-2.5 pt-2">
                    <div className="mb-1.5 truncate font-mono text-[10.5px] text-muted-foreground" title={b.label}>{b.label}</div>
                    <TransitLine nodes={b.nodes} index={index} depth={depth + 1} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}

/** Compact one-row preview for the flow list. */
export function LinePreview({ stops }: { stops: LineStop[] }) {
  return (
    <span className="flex items-center" aria-label={`${stops.length} steps`}>
      {stops.slice(0, 12).map((s, i) => (
        <span key={i} className="flex items-center">
          {i > 0 && <span aria-hidden className="h-px w-2.5 bg-border-2" />}
          <span
            aria-hidden
            className={cn(
              'inline-block h-2 w-2 rounded-full border-[1.5px]',
              s === 'read' && 'border-muted-foreground',
              s === 'write' && 'border-warning bg-warning',
              s === 'destructive' && 'border-destructive bg-destructive',
              s === 'gate' && 'rounded-[1px] border-warning',
              (s === 'fork' || s === 'loop') && 'rounded-[1px] border-foreground',
              (s === 'search' || s === 'judge' || s === 'email' || s === 'pass') && 'border-primary',
            )}
          />
        </span>
      ))}
      {stops.length > 12 && <span className="ml-1 font-mono text-[10px] text-muted-foreground">+{stops.length - 12}</span>}
    </span>
  );
}

// ── NAN-4546: mock FlowLine (soar3-flow.jsx:23) ─────────────────────────

export type LineGlyph = 'read' | 'write' | 'destructive' | 'gate' | 'fork';

/** Flattened station sequence: branches follow their first arm, loops inline their body. */
export function flowGlyphs(nodes: FlowNode[], index: Map<string, IndexedAction>): LineGlyph[] {
  const out: LineGlyph[] = [];
  const visit = (list: FlowNode[]) => {
    for (const n of list) {
      if (n.kind === 'action') out.push(asEffect(lookupAction(index, n.pack, n.action)?.action.effect) ?? 'write');
      else if (n.kind === 'approval') out.push('gate');
      else if (n.kind === 'search' || n.kind === 'judge') out.push('read');
      else if (n.kind === 'email') out.push('write');
      else if (n.kind === 'branchone' || n.kind === 'branchall') {
        out.push('fork');
        if (n.branches[0]) visit(n.branches[0].nodes);
      } else if (n.kind === 'loop') visit(n.branches[0]?.nodes ?? []);
    }
  };
  visit(nodes);
  return out;
}

const HATCH_BG = 'repeating-linear-gradient(135deg, color-mix(in srgb, var(--destructive) 75%, transparent) 0 1.5px, transparent 1.5px 4px)';
const WAIT_BG = 'repeating-linear-gradient(135deg, color-mix(in srgb, var(--warning) 35%, transparent) 0 1.5px, transparent 1.5px 5px)';

export function FlowLine({ glyphs }: { glyphs: LineGlyph[] }) {
  return (
    <div className="flex items-center" aria-label={`${glyphs.length} stations`} data-testid="flow-line">
      <span aria-hidden className="h-2.5 w-2.5 shrink-0 rounded-[3px] border-2 border-primary" />
      {glyphs.slice(0, 10).map((k, i) => (
        <span key={i} className="flex items-center">
          <span aria-hidden className="h-[2px] w-7 bg-fg-4" />
          {k === 'fork' ? (
            <span aria-hidden className="h-2.5 w-2.5 rotate-45 border-2 border-primary" />
          ) : k === 'gate' ? (
            <span aria-hidden className="h-3 w-2.5 border-x-2 border-warning" style={{ background: WAIT_BG }} />
          ) : (
            <span
              aria-hidden
              className="h-3 w-3 rounded-full"
              style={k === 'read' ? { border: '2px solid var(--fg-2)' } : k === 'write' ? { background: 'var(--warning)' } : { background: HATCH_BG, border: '1.5px solid var(--destructive)' }}
            />
          )}
        </span>
      ))}
      {glyphs.length > 10 && <span className="ml-1 font-mono text-[10px] text-muted-foreground">+{glyphs.length - 10}</span>}
      <span aria-hidden className="h-[2px] w-5 bg-fg-4" />
      <span aria-hidden className="h-2 w-2 rounded-full bg-muted-foreground" />
    </div>
  );
}
