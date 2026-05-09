// SPDX-License-Identifier: AGPL-3.0-or-later

import { bandColor, LATERAL_METHOD_LABEL, methodColor } from './helpers';
import type { LateralEdge, LateralNode } from './types';

interface LateralEdgeDrawerProps {
  edge: LateralEdge;
  nodes: LateralNode[];
  onClose: () => void;
  onPivotEvents: (edge: LateralEdge) => void;
}

export function LateralEdgeDrawer({
  edge,
  nodes,
  onClose,
  onPivotEvents,
}: LateralEdgeDrawerProps) {
  const src = nodes.find((n) => n.id === edge.from);
  const dst = nodes.find((n) => n.id === edge.to);
  const color = methodColor(edge.method);
  const label = LATERAL_METHOD_LABEL[edge.method] ?? edge.method;

  const group = edge.method.startsWith('auth-')
    ? 'Authentication'
    : edge.method.startsWith('network-')
    ? 'Network connection'
    : 'Process / remote exec';

  const verb = edge.method.startsWith('auth-')
    ? 'authenticated to'
    : edge.method.startsWith('network-')
    ? 'connected to'
    : 'executed code on';

  return (
    <div className="flex flex-col h-full bg-card border-l border-border min-w-0">
      <div className="px-3 py-3 border-b border-border shrink-0">
        <div className="flex items-start gap-3">
          <div
            className="min-w-[36px] h-9 px-2 rounded-md flex items-center justify-center shrink-0 whitespace-nowrap"
            style={{
              background: `${color}22`,
              color,
              border: `1px solid ${color}55`,
            }}
          >
            <span className="font-mono text-[9.5px] tracking-wider font-semibold">
              {label}
            </span>
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5">
              <span className="font-mono text-[12px] text-foreground truncate">
                {src?.label ?? edge.from}
              </span>
              <span className="text-muted-foreground/70">→</span>
              <span className="font-mono text-[12px] text-foreground truncate">
                {dst?.label ?? edge.to}
              </span>
            </div>
            <div className="font-mono text-[10.5px] text-muted-foreground/80 mt-0.5">{group}</div>
            <div className="font-mono text-[10px] text-muted-foreground/70 mt-1 flex items-center gap-2">
              <span>
                first <span className="text-muted-foreground/90">{edge.firstSeen}</span>
              </span>
              <span>·</span>
              <span className="tabular-nums">
                {edge.count.toLocaleString()} observation{edge.count === 1 ? '' : 's'}
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-muted-foreground/70 hover:text-foreground shrink-0 text-[16px] leading-none px-1"
            aria-label="Close"
          >
            ✕
          </button>
        </div>
      </div>

      <div className="px-3 py-3 border-b border-border shrink-0">
        <div className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-muted-foreground/70 mb-1.5">
          Detail
        </div>
        <div className="font-mono text-[11px] text-foreground break-words">{edge.detail}</div>
      </div>

      <div className="px-3 py-3 shrink-0">
        <div className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-muted-foreground/70 mb-1.5">
          Reasoning
        </div>
        <ul className="font-mono text-[10.5px] text-muted-foreground/80 space-y-1 list-disc pl-4">
          <li>
            Edge added because <span className="text-foreground">{src?.label ?? edge.from}</span>{' '}
            <span className="text-muted-foreground/80">{verb}</span>{' '}
            <span className="text-foreground">{dst?.label ?? edge.to}</span> within the analysis
            window.
          </li>
          <li>
            Severity{' '}
            <span style={{ color: bandColor(edge.band) }}>{edge.band}</span> —{' '}
            {edge.band === 'critical'
              ? 'crown-jewel reached or credential access observed'
              : edge.band === 'high'
              ? 'first-time peer + admin share'
              : 'within normal population'}
            .
          </li>
          <li>{edge.count.toLocaleString()} raw events collapsed into this edge.</li>
        </ul>
      </div>

      <div className="flex-1" />

      <div className="border-t border-border px-3 py-2 shrink-0 flex items-center gap-1.5">
        <button
          onClick={() => onPivotEvents(edge)}
          className="px-2 py-1 rounded-md border border-border hover:border-foreground/40 bg-foreground/[0.02] hover:bg-foreground/[0.04] font-mono text-[10px] text-foreground"
        >
          Show underlying events
        </button>
      </div>
    </div>
  );
}
