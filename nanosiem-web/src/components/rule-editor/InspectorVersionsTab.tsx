// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-489 — Inspector Versions tab.
//
// Full timeline + inline diff + revert. Replaces the earlier Versions card
// in the BottomTray that showed only the top 4 with no diff and no action.
// Stays in the redesign — no redirect-to-legacy escape hatch.

import { useEffect, useMemo, useState } from 'react';
import { diffLines, type Change } from 'diff';
import { Clock, History, Loader2, RotateCcw, User } from 'lucide-react';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useRevertRuleVersion, useRuleVersions } from '@/hooks/use-api';
import type { RuleVersionResponse } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';

interface InspectorVersionsTabProps {
  ruleId: string | undefined;
  /** Current editor body — diffed against the selected version. */
  currentQuery: string;
  /** Called after a successful revert so the editor can refetch + reseed. */
  onReverted?: () => void;
  disabled?: boolean;
  /**
   * Externally requested version selection — when set (e.g. user clicked a
   * chip in the BottomTray), select the matching version once it loads.
   * Caller should clear the request via `onFocusConsumed` after we react.
   */
  focusVersionId?: number | string | null;
  onFocusConsumed?: () => void;
}

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diffMs = Date.now() - then;
  const sec = Math.max(1, Math.floor(diffMs / 1000));
  if (sec < 60) return 'just now';
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  const mo = Math.floor(day / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(mo / 12)}y ago`;
}

function normalizeQuery(query: string): string {
  // Pipe stages on their own lines so a reformat doesn't read as a full diff.
  return query
    .replace(/\s*\|\s*/g, '\n| ')
    .split('\n')
    .map((l) => l.trimEnd())
    .filter((l) => l.length > 0)
    .join('\n');
}

function DiffView({ original, current }: { original: string; current: string }) {
  const changes = useMemo<Change[]>(
    () => diffLines(normalizeQuery(original), normalizeQuery(current)),
    [original, current],
  );

  return (
    <div className="rounded-md border border-border overflow-hidden bg-[var(--card)]">
      <div className="px-2.5 py-1 border-b border-border flex items-center gap-3 text-[9.5px] font-mono uppercase tracking-[0.1em] text-muted-foreground">
        <span className="flex items-center gap-1">
          <span className="inline-block w-2 h-2 rounded-sm bg-[var(--destructive)]/20 border border-[var(--destructive)]/40" />
          Removed
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block w-2 h-2 rounded-sm bg-[var(--success)]/20 border border-[var(--success)]/40" />
          Added
        </span>
        <span className="ml-auto">selected vs current</span>
      </div>
      <div className="max-h-60 overflow-y-auto text-[11px] font-mono leading-[1.5]">
        {changes.length === 0 && (
          <div className="px-3 py-2 text-muted-foreground">No differences.</div>
        )}
        {changes.map((change, i) => {
          const lines = change.value.replace(/\n$/, '').split('\n');
          const tone = change.added
            ? 'text-[var(--success)] bg-[var(--success)]/10'
            : change.removed
              ? 'text-[var(--destructive)] bg-[var(--destructive)]/10'
              : 'text-muted-foreground/80';
          const prefix = change.added ? '+' : change.removed ? '-' : ' ';
          return (
            <div key={i}>
              {lines.map((line, j) => (
                <div key={`${i}-${j}`} className={cn('px-2.5 py-[1px] whitespace-pre', tone)}>
                  <span className="inline-block w-3 text-center select-none opacity-60">{prefix}</span>
                  {line || '\u00A0'}
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function InspectorVersionsTab({
  ruleId,
  currentQuery,
  onReverted,
  disabled,
  focusVersionId,
  onFocusConsumed,
}: InspectorVersionsTabProps) {
  const { data: versions, loading, refetch } = useRuleVersions(ruleId);
  const { mutate: revert, loading: reverting } = useRevertRuleVersion();
  const [selected, setSelected] = useState<RuleVersionResponse | null>(null);
  const [confirming, setConfirming] = useState<RuleVersionResponse | null>(null);

  const list = versions || [];

  useEffect(() => {
    if (focusVersionId == null) return;
    const match = list.find((v) => String(v.id) === String(focusVersionId));
    if (match) {
      setSelected(match);
      onFocusConsumed?.();
    }
    // If list hasn't loaded yet, wait — the request stays pending until the
    // versions arrive, then this effect re-runs and resolves it.
  }, [focusVersionId, list, onFocusConsumed]);

  const handleRevert = async () => {
    if (!ruleId || !confirming) return;
    try {
      await revert({ ruleId, versionId: confirming.id });
      toast.success(`Reverted to v${confirming.version_number}`);
      setConfirming(null);
      setSelected(null);
      refetch();
      onReverted?.();
    } catch {
      toast.error('Failed to revert rule');
    }
  };

  if (!ruleId) {
    return (
      <div className="flex-1 min-h-0 flex items-center justify-center px-6">
        <div className="text-center">
          <History className="w-5 h-5 mx-auto mb-1.5 text-muted-foreground" strokeWidth={1.5} />
          <div className="text-[11.5px] text-muted-foreground leading-relaxed">
            Version history appears after the first save.
          </div>
        </div>
      </div>
    );
  }

  return (
    <ScrollArea className="flex-1 min-h-0">
      <div className="p-3 space-y-3">
        <div>
          <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.12em] font-semibold text-muted-foreground mb-2">
            <History className="w-3 h-3" strokeWidth={1.75} />
            Version history
            {list.length > 0 && (
              <span className="ml-auto text-muted-foreground/70 normal-case tracking-normal font-sans text-[10.5px]">
                {list.length} version{list.length === 1 ? '' : 's'}
              </span>
            )}
          </div>
          <div className="text-[11px] text-muted-foreground leading-relaxed mb-3">
            Every save records a version. Select one to preview the diff and revert if needed.
          </div>
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground px-2 py-3">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            Loading versions…
          </div>
        )}

        {!loading && list.length === 0 && (
          <div className="text-[11.5px] text-muted-foreground px-2">
            No history yet — the next save will record v1.
          </div>
        )}

        {!loading && list.length > 0 && (
          <div className="space-y-1.5">
            {list.map((v) => {
              const active = selected?.id === v.id;
              return (
                <button
                  key={v.id}
                  type="button"
                  onClick={() => setSelected(active ? null : v)}
                  className={cn(
                    'w-full text-left px-2.5 py-1.5 rounded-md transition-colors border cursor-pointer',
                    active
                      ? 'bg-primary/10 border-primary/40'
                      : 'border-transparent hover:bg-foreground/5 hover:border-border',
                  )}
                >
                  <div className="flex items-baseline gap-2">
                    <span className="font-mono text-[12px] font-semibold text-foreground">
                      v{v.version_number}
                    </span>
                    {v.is_active && (
                      <span className="text-[9.5px] font-mono uppercase tracking-[0.08em] text-[var(--success)]">
                        current
                      </span>
                    )}
                    <span className="ml-auto inline-flex items-center gap-1 text-[10.5px] font-mono text-muted-foreground">
                      <Clock className="w-2.5 h-2.5" strokeWidth={1.75} />
                      {relativeTime(v.created_at)}
                    </span>
                  </div>
                  {(v.created_by_name || v.change_reason) && (
                    <div className="mt-0.5 flex items-center gap-2 text-[10.5px] text-muted-foreground">
                      {v.created_by_name && (
                        <span className="inline-flex items-center gap-1">
                          <User className="w-2.5 h-2.5" strokeWidth={1.75} />
                          {v.created_by_name}
                        </span>
                      )}
                      {v.change_reason && <span className="truncate italic">— {v.change_reason}</span>}
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        )}

        {selected && (
          <div className="space-y-2 pt-2 border-t border-border">
            <div className="flex items-center justify-between gap-2">
              <div className="text-[11.5px] text-foreground">
                <span className="font-mono font-semibold">v{selected.version_number}</span>{' '}
                <span className="text-muted-foreground">
                  by {selected.created_by_name || 'unknown'} · {relativeTime(selected.created_at)}
                </span>
              </div>
              {!selected.is_active && (
                <Button
                  onClick={() => setConfirming(selected)}
                  disabled={disabled || reverting}
                  className="h-7 text-[11px] gap-1.5 bg-[var(--warning,_#D08770)]/20 hover:bg-[var(--warning,_#D08770)]/30 text-foreground border border-[var(--warning,_#D08770)]/40"
                >
                  <RotateCcw className="w-3 h-3" strokeWidth={1.75} />
                  Revert
                </Button>
              )}
            </div>
            <DiffView original={selected.query} current={currentQuery} />
          </div>
        )}

        <AlertDialog
          open={confirming !== null}
          onOpenChange={(open) => {
            if (!open) setConfirming(null);
          }}
        >
          <AlertDialogContent className="max-w-md gap-0 p-0 bg-card border-border text-foreground">
            <AlertDialogHeader className="border-b border-border px-5 py-4">
              <AlertDialogTitle className="flex items-center gap-2 text-[14px] font-semibold">
                <RotateCcw className="w-4 h-4 text-[var(--warning,_#D08770)]" strokeWidth={1.75} />
                Revert to v{confirming?.version_number}?
              </AlertDialogTitle>
              <AlertDialogDescription className="font-mono text-[11px] text-muted-foreground leading-relaxed">
                Replaces the current rule body with the selected version. A new version entry
                records the revert so you can walk back if needed.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter className="border-t border-border px-5 py-3">
              <AlertDialogCancel className="h-8 text-[11.5px] bg-accent/50 border-border text-foreground hover:bg-accent">
                Cancel
              </AlertDialogCancel>
              <AlertDialogAction
                className="h-8 text-[11.5px] gap-1.5 bg-[var(--warning,_#D08770)] text-white hover:bg-[var(--warning,_#D08770)]/90"
                onClick={handleRevert}
                disabled={reverting}
              >
                {reverting && <Loader2 className="w-3 h-3 animate-spin" />}
                Revert rule
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </ScrollArea>
  );
}
