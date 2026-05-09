// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useMemo, useCallback, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import * as Diff from 'diff';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  Loader2,
  Check,
  X,
  CircleCheck,
  XCircle,
  RotateCcw,
  ArrowRight,
} from 'lucide-react';
import { api } from '@/lib/api';

interface UpstreamMergeModalProps {
  detectionRuleId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onApplyMerge: (mergedQuery: string) => void;
}

interface Hunk {
  id: number;
  oldStart: number;
  oldLines: string[];
  newStart: number;
  newLines: string[];
  accepted: boolean | null; // null = undecided, true = accept upstream, false = keep current
}

function parseHunks(oldText: string, newText: string): Hunk[] {
  const changes = Diff.diffLines(oldText, newText);
  const hunks: Hunk[] = [];

  let oldLineNum = 1;
  let newLineNum = 1;
  let hunkId = 0;

  let currentOldLines: string[] = [];
  let currentNewLines: string[] = [];
  let hunkOldStart = oldLineNum;
  let hunkNewStart = newLineNum;
  let inChange = false;

  const flushHunk = () => {
    if (currentOldLines.length > 0 || currentNewLines.length > 0) {
      hunks.push({
        id: hunkId++,
        oldStart: hunkOldStart,
        oldLines: [...currentOldLines],
        newStart: hunkNewStart,
        newLines: [...currentNewLines],
        accepted: null,
      });
      currentOldLines = [];
      currentNewLines = [];
    }
  };

  for (const change of changes) {
    const lines = change.value.split('\n');
    // Remove trailing empty line from split
    if (lines[lines.length - 1] === '') {
      lines.pop();
    }

    if (change.added || change.removed) {
      if (!inChange) {
        // Starting a new hunk
        hunkOldStart = oldLineNum;
        hunkNewStart = newLineNum;
        inChange = true;
      }

      if (change.removed) {
        currentOldLines.push(...lines);
        oldLineNum += lines.length;
      } else {
        currentNewLines.push(...lines);
        newLineNum += lines.length;
      }
    } else {
      // Unchanged - flush any pending hunk
      if (inChange) {
        flushHunk();
        inChange = false;
      }
      oldLineNum += lines.length;
      newLineNum += lines.length;
    }
  }

  // Flush final hunk if any
  if (inChange) {
    flushHunk();
  }

  return hunks;
}

function applyHunkDecisions(oldText: string, newText: string, hunks: Hunk[]): string {
  const changes = Diff.diffLines(oldText, newText);
  const result: string[] = [];

  let hunkIndex = 0;
  let oldLineNum = 1;
  let newLineNum = 1;

  for (const change of changes) {
    const lines = change.value.split('\n');
    if (lines[lines.length - 1] === '') {
      lines.pop();
    }

    if (!change.added && !change.removed) {
      // Unchanged - always include
      result.push(...lines);
      oldLineNum += lines.length;
      newLineNum += lines.length;
    } else {
      // Find the corresponding hunk
      const hunk = hunks[hunkIndex];

      if (change.removed) {
        // This is the "old" part of a hunk
        if (hunk && hunk.accepted === false) {
          // Keep current (old) version
          result.push(...lines);
        }
        // If accepted === true or null, we skip old lines (will use new ones)
        oldLineNum += lines.length;
      } else if (change.added) {
        // This is the "new" part of a hunk
        if (hunk && (hunk.accepted === true || hunk.accepted === null)) {
          // Accept upstream (new) version - null defaults to accept
          result.push(...lines);
        }
        // If accepted === false, we skip new lines (already added old ones)
        newLineNum += lines.length;

        // Move to next hunk after processing the "new" part
        // (assuming hunks are removed+added pairs)
        if (hunk && hunkIndex < hunks.length) {
          hunkIndex++;
        }
      }
    }
  }

  return result.join('\n');
}

function HunkView({
  hunk,
  onAccept,
  onReject,
  onReset
}: {
  hunk: Hunk;
  onAccept: () => void;
  onReject: () => void;
  onReset: () => void;
}) {
  const hasOld = hunk.oldLines.length > 0;
  const hasNew = hunk.newLines.length > 0;

  return (
    <div className={`border rounded-lg overflow-hidden ${
      hunk.accepted === true
        ? 'border-green-500/50 bg-green-500/5'
        : hunk.accepted === false
        ? 'border-red-500/50 bg-red-500/5'
        : 'border-border'
    }`}>
      {/* Hunk header */}
      <div className="flex items-center justify-between px-3 py-2 bg-muted/50 border-b">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {hasOld && hasNew ? (
            <span>Lines modified</span>
          ) : hasNew ? (
            <span className="text-green-600">Lines added</span>
          ) : (
            <span className="text-red-600">Lines removed</span>
          )}
          {hunk.accepted !== null && (
            <Badge variant="outline" className={`text-xs ${
              hunk.accepted ? 'text-green-600 border-green-600' : 'text-amber-600 border-amber-600'
            }`}>
              {hunk.accepted ? 'Will accept upstream' : 'Will keep yours'}
            </Badge>
          )}
        </div>
        <TooltipProvider>
          <div className="flex items-center gap-1">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className={`h-7 px-2 ${hunk.accepted === false ? 'bg-amber-500/20' : ''}`}
                  onClick={onReject}
                >
                  <XCircle className="w-4 h-4 mr-1 text-amber-600" />
                  Keep Mine
                </Button>
              </TooltipTrigger>
              <TooltipContent>Keep your current version</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className={`h-7 px-2 ${hunk.accepted === true ? 'bg-green-500/20' : ''}`}
                  onClick={onAccept}
                >
                  <CircleCheck className="w-4 h-4 mr-1 text-green-600" />
                  Accept
                </Button>
              </TooltipTrigger>
              <TooltipContent>Accept upstream changes</TooltipContent>
            </Tooltip>
            {hunk.accepted !== null && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2"
                    onClick={onReset}
                  >
                    <RotateCcw className="w-3 h-3" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Reset decision</TooltipContent>
              </Tooltip>
            )}
          </div>
        </TooltipProvider>
      </div>

      {/* Hunk content */}
      <div className="font-mono text-sm">
        {/* Old lines (current/yours) - shown with strikethrough if accepting upstream */}
        {hunk.oldLines.map((line, idx) => (
          <div
            key={`old-${idx}`}
            className={`flex ${
              hunk.accepted === true
                ? 'bg-red-500/10 text-red-400 line-through opacity-50'
                : 'bg-red-500/15 text-red-700 dark:text-red-300'
            }`}
          >
            <div className="w-6 flex-shrink-0 text-center select-none bg-red-500/25 text-red-600">
              -
            </div>
            <pre className="flex-1 px-2 py-0.5 whitespace-pre-wrap break-all">
              {line || ' '}
            </pre>
          </div>
        ))}
        {/* Arrow indicator between old and new */}
        {hasOld && hasNew && (
          <div className="flex items-center justify-center py-1 bg-muted/30 text-muted-foreground">
            <ArrowRight className="w-4 h-4" />
          </div>
        )}
        {/* New lines (upstream) - shown with strikethrough if keeping current */}
        {hunk.newLines.map((line, idx) => (
          <div
            key={`new-${idx}`}
            className={`flex ${
              hunk.accepted === false
                ? 'bg-green-500/10 text-green-400 line-through opacity-50'
                : 'bg-green-500/15 text-green-700 dark:text-green-300'
            }`}
          >
            <div className="w-6 flex-shrink-0 text-center select-none bg-green-500/25 text-green-600">
              +
            </div>
            <pre className="flex-1 px-2 py-0.5 whitespace-pre-wrap break-all">
              {line || ' '}
            </pre>
          </div>
        ))}
      </div>
    </div>
  );
}

export function UpstreamMergeModal({
  detectionRuleId,
  open,
  onOpenChange,
  onApplyMerge,
}: UpstreamMergeModalProps) {
  // Fetch the diff
  const { data: diff, isLoading } = useQuery({
    queryKey: ['upstream-diff', detectionRuleId],
    queryFn: () => api.ruleRepositories.getUpstreamDiff(detectionRuleId),
    enabled: open,
  });

  // Parse hunks from diff
  const initialHunks = useMemo(() => {
    if (!diff) return [];
    return parseHunks(diff.current_query, diff.upstream_query);
  }, [diff]);

  const [hunks, setHunks] = useState<Hunk[]>([]);

  // Reset hunks when diff changes
  useEffect(() => {
    setHunks(initialHunks);
  }, [initialHunks]);

  const updateHunk = useCallback((id: number, accepted: boolean | null) => {
    setHunks(prev => prev.map(h => h.id === id ? { ...h, accepted } : h));
  }, []);

  const acceptAll = useCallback(() => {
    setHunks(prev => prev.map(h => ({ ...h, accepted: true })));
  }, []);

  const rejectAll = useCallback(() => {
    setHunks(prev => prev.map(h => ({ ...h, accepted: false })));
  }, []);

  const resetAll = useCallback(() => {
    setHunks(initialHunks);
  }, [initialHunks]);

  // Compute merged result
  const mergedQuery = useMemo(() => {
    if (!diff) return '';
    return applyHunkDecisions(diff.current_query, diff.upstream_query, hunks);
  }, [diff, hunks]);

  // Stats
  const stats = useMemo(() => {
    const total = hunks.length;
    const accepted = hunks.filter(h => h.accepted === true).length;
    const rejected = hunks.filter(h => h.accepted === false).length;
    const undecided = hunks.filter(h => h.accepted === null).length;
    return { total, accepted, rejected, undecided };
  }, [hunks]);

  const handleApply = () => {
    onApplyMerge(mergedQuery);
    onOpenChange(false);
  };

  // Check if queries are identical
  const queriesMatch = diff?.upstream_query === diff?.current_query;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle>Merge Upstream Changes</DialogTitle>
          <DialogDescription>
            Review each change and decide whether to accept the upstream version or keep yours.
            {diff?.file_path && (
              <span className="block font-mono text-xs mt-1">{diff.file_path}</span>
            )}
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
          </div>
        ) : queriesMatch ? (
          <div className="flex-1 flex items-center justify-center py-12">
            <div className="text-center">
              <Check className="w-12 h-12 mx-auto mb-4 text-green-500" />
              <p className="text-lg font-medium">Queries are identical</p>
              <p className="text-muted-foreground">No changes to merge.</p>
            </div>
          </div>
        ) : diff && hunks.length > 0 ? (
          <div className="space-y-4">
            {/* Bulk actions */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4 text-sm">
                <span className="text-muted-foreground">
                  {stats.total} change{stats.total !== 1 ? 's' : ''}
                </span>
                {stats.accepted > 0 && (
                  <Badge variant="outline" className="text-green-600 border-green-600">
                    <Check className="w-3 h-3 mr-1" />
                    {stats.accepted} accepting
                  </Badge>
                )}
                {stats.rejected > 0 && (
                  <Badge variant="outline" className="text-amber-600 border-amber-600">
                    <X className="w-3 h-3 mr-1" />
                    {stats.rejected} keeping mine
                  </Badge>
                )}
                {stats.undecided > 0 && (
                  <Badge variant="outline" className="text-muted-foreground">
                    {stats.undecided} undecided
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" onClick={acceptAll}>
                  <CircleCheck className="w-4 h-4 mr-1 text-green-600" />
                  Accept All
                </Button>
                <Button variant="outline" size="sm" onClick={rejectAll}>
                  <XCircle className="w-4 h-4 mr-1 text-amber-600" />
                  Keep All Mine
                </Button>
                <Button variant="ghost" size="sm" onClick={resetAll}>
                  <RotateCcw className="w-4 h-4 mr-1" />
                  Reset
                </Button>
              </div>
            </div>

            {/* Hunks */}
            <div className="overflow-y-auto pr-1" style={{ maxHeight: 'calc(90vh - 260px)' }}>
              <div className="space-y-4 pr-3">
                {hunks.map((hunk) => (
                  <HunkView
                    key={hunk.id}
                    hunk={hunk}
                    onAccept={() => updateHunk(hunk.id, true)}
                    onReject={() => updateHunk(hunk.id, false)}
                    onReset={() => updateHunk(hunk.id, null)}
                  />
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center py-8 text-muted-foreground">
            Failed to load diff
          </div>
        )}

        <DialogFooter className="flex-shrink-0">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleApply}
            disabled={!diff || queriesMatch}
          >
            <Check className="w-4 h-4 mr-2" />
            Apply Merged Changes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
