// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { bandColor, fmtCount, NodeIcon } from './helpers';
import type { LateralEvidence, LateralNode } from './types';

const TABS = ['Auth', 'Network', 'Process'] as const;
type Tab = (typeof TABS)[number];

function FlagPill({ t }: { t: string }) {
  return (
    <span className="inline-flex items-center gap-1 px-1.5 rounded-sm font-mono text-[9.5px] tracking-wide uppercase text-[oklch(68%_0.18_28)] bg-[oklch(68%_0.18_28/0.12)] border border-[oklch(68%_0.18_28/0.35)]">
      {t}
    </span>
  );
}

interface LateralNodeDrawerProps {
  node: LateralNode;
  evidence: LateralEvidence | null;
  onClose: () => void;
  onPivotEvents: (node: LateralNode) => void;
  onPivotAsset: (node: LateralNode) => void;
  onCopyQuery: (node: LateralNode) => void;
}

export function LateralNodeDrawer({
  node,
  evidence,
  onClose,
  onPivotEvents,
  onPivotAsset,
  onCopyQuery,
}: LateralNodeDrawerProps) {
  const [tab, setTab] = useState<Tab>('Auth');
  const ev = evidence ?? { auth: [], network: [], process: [] };
  const rows = ev[tab.toLowerCase() as keyof LateralEvidence] ?? [];
  const color = bandColor(node.band);

  return (
    <div className="flex flex-col h-full bg-card border-l border-border min-w-0">
      {/* Head */}
      <div className="px-3 py-3 border-b border-border shrink-0">
        <div className="flex items-start gap-2.5">
          <div
            className="w-9 h-9 rounded-md flex items-center justify-center shrink-0"
            style={{
              background: `${color}22`,
              color,
              border: `1px solid ${color}55`,
            }}
          >
            <NodeIcon type={node.type} className="w-4 h-4" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5">
              <span className="font-mono text-[13px] text-foreground truncate">{node.label}</span>
              <span
                className="w-1.5 h-1.5 rounded-full shrink-0"
                style={{ background: color }}
              />
              <span
                className="font-mono text-[9.5px] uppercase tracking-[0.12em]"
                style={{ color }}
              >
                {node.band}
              </span>
            </div>
            <div className="font-mono text-[10.5px] text-muted-foreground/80 truncate">
              {node.sub}
            </div>
            <div className="font-mono text-[10px] text-muted-foreground/70 mt-1 flex items-center gap-2 flex-wrap">
              <span>
                first seen <span className="text-muted-foreground/90">{node.firstSeen}</span>
              </span>
              <span>·</span>
              <span>{fmtCount(node.events)} events</span>
              {node.role && (
                <>
                  <span>·</span>
                  <span className="text-muted-foreground/80 uppercase tracking-wide text-[9px]">
                    {node.role}
                  </span>
                </>
              )}
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

        {node.flags && node.flags.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {node.flags.map((f, i) => (
              <FlagPill key={i} t={f} />
            ))}
          </div>
        )}

        {/* Pivot actions */}
        <div className="mt-2.5 grid grid-cols-2 gap-1 font-mono text-[10px]">
          <button
            onClick={() => onPivotEvents(node)}
            className="px-2 py-1 rounded-md border border-border hover:border-foreground/40 bg-foreground/[0.02] hover:bg-foreground/[0.04] text-foreground text-left"
          >
            Pivot to events
          </button>
          {node.type === 'host' && (
            <button
              onClick={() => onPivotAsset(node)}
              className="px-2 py-1 rounded-md border border-border hover:border-foreground/40 bg-foreground/[0.02] hover:bg-foreground/[0.04] text-foreground text-left"
            >
              Open asset view
            </button>
          )}
          {node.type === 'user' && (
            <button
              onClick={() => onPivotAsset(node)}
              className="px-2 py-1 rounded-md border border-border hover:border-foreground/40 bg-foreground/[0.02] hover:bg-foreground/[0.04] text-foreground text-left"
            >
              Pivot to user
            </button>
          )}
          <button
            onClick={() => onCopyQuery(node)}
            className="px-2 py-1 rounded-md border border-border hover:border-foreground/40 bg-foreground/[0.02] hover:bg-foreground/[0.04] text-foreground text-left"
          >
            Copy as query
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border font-mono text-[11px] shrink-0">
        {TABS.map((t) => {
          const count = (ev[t.toLowerCase() as keyof LateralEvidence] ?? []).length;
          return (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                'flex-1 px-2.5 py-1.5 border-b-2 -mb-px flex items-center justify-center gap-1.5',
                tab === t
                  ? 'border-primary text-foreground'
                  : 'border-transparent text-muted-foreground/80 hover:text-foreground'
              )}
            >
              <span>{t}</span>
              <span
                className={cn(
                  'text-[10px]',
                  tab === t ? 'text-muted-foreground/80' : 'text-muted-foreground/60'
                )}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Body */}
      <div className="flex-1 overflow-auto">
        {rows.length === 0 ? (
          <div className="px-4 py-8 text-center font-mono text-[10.5px] text-muted-foreground/70">
            No {tab.toLowerCase()} evidence in window. Widen the time range or switch tabs.
          </div>
        ) : (
          rows.map((r, i) => (
            <div
              key={i}
              className="px-3 py-1.5 border-b border-border/60 font-mono text-[11px] hover:bg-foreground/[0.02]"
            >
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground/70 w-12 shrink-0">{r.at}</span>
                {tab === 'Auth' && (
                  <>
                    <span className="text-foreground truncate flex-1">
                      {r.user || node.label}{' '}
                      <span className="text-muted-foreground/70">via</span>{' '}
                      {r.logonType || 'logon'}
                      {r.source && (
                        <>
                          {' '}
                          <span className="text-muted-foreground/70">from</span>{' '}
                          <span className="text-foreground">{r.source}</span>
                        </>
                      )}
                    </span>
                    <span
                      className={cn(
                        'font-mono text-[9.5px] uppercase tracking-wide shrink-0',
                        /success/i.test(r.result ?? '')
                          ? 'text-primary'
                          : 'text-[oklch(76%_0.15_60)]'
                      )}
                    >
                      {/success/i.test(r.result ?? '') ? '✓' : '!'}
                    </span>
                  </>
                )}
                {tab === 'Network' && (
                  <>
                    <span className="text-foreground truncate flex-1">
                      <span className="text-foreground">{r.peer}</span>{' '}
                      <span className="text-muted-foreground/70">:{r.port}</span>{' '}
                      <span className="text-muted-foreground/80">{r.proto}</span>
                    </span>
                  </>
                )}
                {tab === 'Process' && (
                  <>
                    <span className="text-foreground truncate flex-1">
                      {r.name && <span>{r.name}</span>}
                      {r.host && (
                        <>
                          {' '}
                          <span className="text-muted-foreground/70">on</span>{' '}
                          <span className="text-foreground">{r.host}</span>
                        </>
                      )}
                    </span>
                  </>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
