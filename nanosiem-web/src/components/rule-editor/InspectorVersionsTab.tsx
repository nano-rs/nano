// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-489 — Inspector Versions tab.
//
// Full timeline + inline diff + revert. Replaces the earlier Versions card
// in the BottomTray that showed only the top 4 with no diff and no action.
// Stays in the redesign — no redirect-to-legacy escape hatch.
//
// NAN-3023: timeline rows (marker · version + message · time/author) with the
// diff + revert expanding inline under the selected row, per the "Rules pivt
// Panel" handoff mapped onto the app type scale.

import { useEffect, useMemo, useState } from 'react';
import { diffLines, type Change } from 'diff';
import { RotateCcw } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
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
import { ScrollArea } from '@/components/ui/scroll-area';
import { useRevertRuleVersion, useRuleVersions } from '@/hooks/use-api';
import type { RuleVersionResponse } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import {
  EmptyState,
  SectionHeading,
  inspectorSecondaryButtonClass,
} from './InspectorPrimitives';
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
    <div className="rounded-md border border-border overflow-hidden bg-input">
      <div className="h-6 px-2 border-b border-border flex items-center gap-3 text-[10px] font-mono uppercase tracking-[0.1em] text-muted-foreground">
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
      <div className="max-h-60 overflow-auto py-1 text-[11px] font-mono leading-[16px]">
        {changes.length === 0 && (
          <div className="px-2 py-1 text-muted-foreground">No differences.</div>
        )}
        {changes.map((change, i) => {
          const lines = change.value.replace(/\n$/, '').split('\n');
          const tone = change.added
            ? 'text-[var(--success)] bg-[var(--success)]/10'
            : change.removed
              ? 'text-[var(--destructive)] bg-[var(--destructive)]/10'
              : 'text-muted-foreground/80';
          const prefix = change.added ? '+' : change.removed ? '−' : ' ';
          return (
            <div key={i}>
              {lines.map((line, j) => (
                <div key={`${i}-${j}`} className={cn('px-1.5 whitespace-pre', tone)}>
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
      <div className="flex-1 min-h-0 p-3 flex flex-col gap-3">
        <SectionHeading badge={0}>History</SectionHeading>
        <EmptyState title="No versions yet">Version history appears after the first save.</EmptyState>
      </div>
    );
  }

  return (
    <ScrollArea className="flex-1 min-h-0">
      <div className="p-3 flex flex-col gap-3">
        <SectionHeading badge={loading ? undefined : list.length}>History</SectionHeading>

        {loading && (
          <div className="flex items-center gap-2 h-7 text-[11.5px] text-muted-foreground">
            <LoadingIcon className="w-3.5 h-3.5" />
            Loading versions…
          </div>
        )}

        {!loading && list.length === 0 && (
          <EmptyState title="No versions yet">
            Each save records a version you can diff and revert. Your next save becomes{' '}
            <span className="font-mono text-fg-2">v1</span>.
          </EmptyState>
        )}

        {!loading && list.length > 0 && (
          <div className="flex flex-col">
            {list.map((v) => {
              const active = selected?.id === v.id;
              return (
                <div key={v.id} className="flex flex-col">
                  <button
                    type="button"
                    onClick={() => setSelected(active ? null : v)}
                    aria-expanded={active}
                    className={cn(
                      'grid grid-cols-[14px_minmax(0,1fr)_auto] items-start gap-2.5 -mx-2 px-2 py-1.5 rounded-md text-left transition-colors cursor-pointer',
                      active ? 'bg-foreground/[0.05]' : 'hover:bg-foreground/[0.04]',
                    )}
                  >
                    <span
                      aria-hidden
                      className={cn(
                        'mt-[5px] w-2 h-2 rounded-full justify-self-center',
                        v.is_active ? 'bg-[var(--success)]' : 'border-[1.5px] border-border-2',
                      )}
                    />
                    <span className="min-w-0 flex flex-col gap-0.5">
                      <span className="flex items-center gap-1.5">
                        <span className="font-mono text-[12px] font-semibold text-foreground">
                          v{v.version_number}
                        </span>
                        {v.is_active && (
                          <span className="px-[5px] py-px rounded-sm bg-[var(--success)]/10 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--success)]">
                            current
                          </span>
                        )}
                      </span>
                      {v.change_reason && (
                        <span className="truncate text-[11.5px] leading-[16px] text-muted-foreground">
                          {v.change_reason}
                        </span>
                      )}
                    </span>
                    <span className="flex flex-col items-end gap-0.5 font-mono text-[10.5px] leading-[16px] text-muted-foreground">
                      <span>{relativeTime(v.created_at)}</span>
                      {v.created_by_name && (
                        <span className="max-w-[96px] truncate">{v.created_by_name}</span>
                      )}
                    </span>
                  </button>

                  {active && (
                    <div className="ml-6 mt-1 mb-2 flex flex-col gap-2 px-3 py-2.5 rounded-lg border border-border bg-card">
                      <DiffView original={v.query} current={currentQuery} />
                      {!v.is_active && (
                        <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => setConfirming(v)}
                            disabled={disabled || reverting}
                            className={inspectorSecondaryButtonClass}
                          >
                            <RotateCcw className="w-3 h-3" strokeWidth={1.5} />
                            Revert to v{v.version_number}
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
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
                <RotateCcw className="w-4 h-4 text-[var(--warning,_#D08770)]" strokeWidth={1.5} />
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
                {reverting && <LoadingIcon className="w-3 h-3" />}
                Revert rule
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </ScrollArea>
  );
}
