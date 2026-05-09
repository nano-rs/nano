// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-483 — Rule logic tab body.
// Ports design-ref/shadcn/matches-view.jsx's LogicTab. Version history is wired
// to `useRuleVersions` (NAN-492); historical-data testing routes into the
// editor's TestDrawer via `?test=1` (NAN-495).

import { useNavigate } from 'react-router-dom';
import { Copy, Pencil, Play, History, FlaskConical } from 'lucide-react';
import type { DetectionRule } from '@/lib/api/types';
import { QueryHighlight } from '@/lib/syntax-highlight';
import { useToast } from '@/hooks/use-toast';
import { useRuleVersions } from '@/hooks/use-api';
import { relTime } from './helpers';

interface LogicTabProps {
  rule: DetectionRule;
}

export function LogicTab({ rule }: LogicTabProps) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { data: versions, loading: versionsLoading } = useRuleVersions(rule.id);
  const topVersions = (versions || []).slice(0, 5);

  const copyQuery = async () => {
    try {
      await navigator.clipboard.writeText(rule.query);
      toast({ title: 'Query copied' });
    } catch {
      toast({ title: 'Copy failed', description: 'Clipboard unavailable.', variant: 'destructive' });
    }
  };

  return (
    <div className="p-5 max-w-[980px]">
      <div className="rounded-lg border border-border overflow-hidden bg-card">
        <div className="px-3 py-2 flex items-center gap-2 border-b border-border">
          <span className="font-mono text-[10.5px] text-muted-foreground">nano-ql</span>
          <span className="ml-auto flex items-center gap-1">
            <button
              type="button"
              onClick={copyQuery}
              className="h-6 px-2 rounded text-[10.5px] text-muted-foreground hover:text-foreground hover:bg-foreground/5 font-mono flex items-center gap-1"
            >
              <Copy className="w-3 h-3" strokeWidth={2} />
              Copy
            </button>
            <button
              type="button"
              onClick={() => navigate(`/rules/editor/${rule.id}`)}
              className="h-6 px-2 rounded text-[10.5px] text-muted-foreground hover:text-foreground hover:bg-foreground/5 font-mono flex items-center gap-1"
            >
              <Pencil className="w-3 h-3" strokeWidth={2} />
              Edit
            </button>
            <button
              type="button"
              onClick={() => navigate(`/search?q=${encodeURIComponent(rule.query)}`)}
              className="h-6 px-2 rounded bg-primary/90 text-[var(--brand-ink)] text-[10.5px] font-mono font-medium flex items-center gap-1"
            >
              <Play className="w-3 h-3" strokeWidth={2} />
              Run in search
            </button>
          </span>
        </div>
        <pre
          className="font-mono text-[12px] leading-[1.7] p-4 text-foreground whitespace-pre-wrap"
          style={{ background: 'color-mix(in srgb, var(--foreground) 2%, transparent)' }}
        >
          <QueryHighlight code={rule.query} />
        </pre>
      </div>

      <div className="mt-4 grid grid-cols-2 @max-[800px]:grid-cols-1 gap-3">
        <div className="rounded-lg border border-border p-3 bg-card">
          <div className="flex items-center gap-2 mb-2">
            <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              Version history
            </span>
            {topVersions.length > 0 && (
              <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                {versions!.length} total
              </span>
            )}
          </div>
          {versionsLoading && topVersions.length === 0 ? (
            <p className="text-[11px] text-muted-foreground/70 leading-[1.55]">Loading versions…</p>
          ) : topVersions.length === 0 ? (
            <p className="text-[11px] text-muted-foreground leading-[1.55]">
              No prior versions. Created{' '}
              <span className="font-mono text-foreground">{rule.created_at.slice(0, 10)}</span>
              {rule.author && <> by <span className="font-mono text-foreground">{rule.author}</span></>}.
            </p>
          ) : (
            <ul className="flex flex-col">
              {topVersions.map((v) => {
                const when = (() => {
                  try {
                    const iso = v.created_at.endsWith('Z') ? v.created_at : `${v.created_at}Z`;
                    return relTime(new Date(iso));
                  } catch {
                    return v.created_at.slice(0, 10);
                  }
                })();
                return (
                  <li key={v.id}>
                    <button
                      type="button"
                      onClick={() => navigate(`/rules/editor/${rule.id}`)}
                      title={v.change_reason || `Open v${v.version_number} in editor`}
                      className="w-full h-7 flex items-center gap-2 px-1.5 -mx-1.5 rounded text-left hover:bg-foreground/5 group"
                    >
                      <History
                        className="w-3 h-3 shrink-0 text-muted-foreground/70 group-hover:text-foreground"
                        strokeWidth={2}
                      />
                      <span className="font-mono text-[11px] text-foreground tabular-nums shrink-0">
                        v{v.version_number}
                      </span>
                      {v.is_active && (
                        <span
                          className="font-mono text-[9px] uppercase tracking-[0.1em] px-1 py-[1px] rounded-sm shrink-0"
                          style={{
                            background: 'color-mix(in srgb, var(--primary) 16%, transparent)',
                            color: 'var(--primary)',
                          }}
                        >
                          current
                        </span>
                      )}
                      <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums shrink-0">
                        {when}
                      </span>
                      {v.created_by_name && (
                        <span className="font-mono text-[10.5px] text-muted-foreground truncate">
                          {v.created_by_name}
                        </span>
                      )}
                      {v.change_reason && (
                        <span className="text-[10.5px] text-muted-foreground/80 truncate ml-auto">
                          {v.change_reason}
                        </span>
                      )}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        <div className="rounded-lg border border-border p-3 bg-card">
          <div className="flex items-center gap-2 mb-2">
            <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              Test against historical data
            </span>
          </div>
          <p className="text-[11px] text-muted-foreground leading-[1.55]">
            Run this rule's query over a historical window to estimate fire rate before changing
            thresholds. Opens the editor's test drawer where you can pick the window, see matches,
            and tweak the query without saving.
          </p>
          <div className="mt-2.5">
            <button
              type="button"
              onClick={() => navigate(`/rules/editor/${rule.id}?test=1`)}
              className="h-7 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5"
            >
              <FlaskConical className="w-3.5 h-3.5" strokeWidth={2} />
              Open test drawer
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
