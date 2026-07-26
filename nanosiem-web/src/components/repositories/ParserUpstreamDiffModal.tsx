// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
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
import { Loader2, Check, X, Minus, Plus, ArrowUpCircle, Rocket } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { useDeployLogSource } from '@/hooks/use-api';
import { PermissionAction } from './PermissionAction';
import {
  repositoryQueryEnabled,
  type ActionAccess,
} from './repository-action-policy';

interface ParserUpstreamDiffModalProps {
  logSourceId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  diffAccess: ActionAccess;
  dismissAccess: ActionAccess;
  applyAccess: ActionAccess;
  deployAccess: ActionAccess;
}

interface DiffLine {
  type: 'added' | 'removed' | 'unchanged';
  content: string;
  lineNumber?: number;
}

function DiffViewer({ oldText, newText }: { oldText: string; newText: string }) {
  const diffLines = useMemo(() => {
    const changes = Diff.diffLines(oldText, newText);
    const lines: DiffLine[] = [];

    let oldLineNum = 1;
    let newLineNum = 1;

    for (const change of changes) {
      const changeLines = change.value.split('\n');
      if (changeLines[changeLines.length - 1] === '') {
        changeLines.pop();
      }

      for (const line of changeLines) {
        if (change.added) {
          lines.push({ type: 'added', content: line, lineNumber: newLineNum++ });
        } else if (change.removed) {
          lines.push({ type: 'removed', content: line, lineNumber: oldLineNum++ });
        } else {
          lines.push({ type: 'unchanged', content: line, lineNumber: newLineNum });
          oldLineNum++;
          newLineNum++;
        }
      }
    }

    return lines;
  }, [oldText, newText]);

  const stats = useMemo(() => {
    const added = diffLines.filter(l => l.type === 'added').length;
    const removed = diffLines.filter(l => l.type === 'removed').length;
    return { added, removed };
  }, [diffLines]);

  if (oldText === newText) {
    return (
      <div className="p-4 text-center text-muted-foreground bg-muted/30 rounded-lg">
        <Check className="w-5 h-5 mx-auto mb-2 text-green-500" />
        No differences - VRL parsers are identical
      </div>
    );
  }

  return (
    <div className="border rounded-lg overflow-hidden">
      <div className="flex items-center gap-4 px-3 py-2 bg-muted/50 border-b text-xs">
        <span className="text-muted-foreground">Changes:</span>
        <span className="flex items-center gap-1 text-green-600 dark:text-green-400">
          <Plus className="w-3 h-3" />
          {stats.added} added
        </span>
        <span className="flex items-center gap-1 text-red-600 dark:text-red-400">
          <Minus className="w-3 h-3" />
          {stats.removed} removed
        </span>
      </div>

      <div className="font-mono text-sm">
        {diffLines.map((line, idx) => (
          <div
            key={idx}
            className={`flex ${
              line.type === 'added'
                ? 'bg-green-500/15 text-green-700 dark:text-green-300'
                : line.type === 'removed'
                ? 'bg-red-500/15 text-red-700 dark:text-red-300'
                : 'text-foreground'
            }`}
          >
            <div className={`w-6 flex-shrink-0 text-center select-none ${
              line.type === 'added'
                ? 'bg-green-500/25 text-green-600'
                : line.type === 'removed'
                ? 'bg-red-500/25 text-red-600'
                : 'bg-muted/50 text-muted-foreground'
            }`}>
              {line.type === 'added' ? '+' : line.type === 'removed' ? '-' : ' '}
            </div>
            <pre className="flex-1 px-2 py-0.5 whitespace-pre-wrap break-all">
              {line.content || ' '}
            </pre>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ParserUpstreamDiffModal({
  logSourceId,
  open,
  onOpenChange,
  diffAccess,
  dismissAccess,
  applyAccess,
  deployAccess,
}: ParserUpstreamDiffModalProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { mutate: deployLogSource, loading: deploying } = useDeployLogSource();
  const [appliedNeedsDeploy, setAppliedNeedsDeploy] = useState(false);

  const { data: diff, isLoading } = useQuery({
    queryKey: ['parser-upstream-diff', logSourceId],
    queryFn: () => api.parserRepositories.getUpstreamDiff(logSourceId),
    enabled: repositoryQueryEnabled(diffAccess, open),
  });

  const dismissMutation = useMutation({
    mutationFn: () => api.parserRepositories.dismissUpstreamChanges(logSourceId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['parser-upstream-updates'] });
      queryClient.invalidateQueries({ queryKey: ['parser-upstream-diff', logSourceId] });
      toast({
        title: 'Changes dismissed',
        description: 'The upstream changes have been acknowledged.',
      });
      onOpenChange(false);
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to dismiss', description: err.message, variant: 'destructive' });
    },
  });

  const applyMutation = useMutation({
    mutationFn: () => api.parserRepositories.applyUpstreamUpdate(logSourceId),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['parser-upstream-updates'] });
      queryClient.invalidateQueries({ queryKey: ['parser-upstream-diff', logSourceId] });
      queryClient.invalidateQueries({ queryKey: ['log-sources'] });
      queryClient.invalidateQueries({ queryKey: ['log-source-draft-status', logSourceId] });
      if (result.needs_deploy) {
        setAppliedNeedsDeploy(true);
      } else {
        toast({ title: 'Update applied', description: result.message });
        onOpenChange(false);
      }
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to apply update', description: err.message, variant: 'destructive' });
    },
  });

  const handleDeployNow = async () => {
    try {
      await deployLogSource(logSourceId);
      queryClient.invalidateQueries({ queryKey: ['log-sources'] });
      queryClient.invalidateQueries({ queryKey: ['log-source-deployments', logSourceId] });
      toast({ title: 'Deployed', description: 'Parser updated and deployed to Vector.' });
      setAppliedNeedsDeploy(false);
      onOpenChange(false);
    } catch (err) {
      toast({ title: 'Deploy failed', description: err instanceof Error ? err.message : 'Failed to deploy', variant: 'destructive' });
    }
  };

  const handleClose = (value: boolean) => {
    if (!value) setAppliedNeedsDeploy(false);
    onOpenChange(value);
  };

  const vrlMatch = diff ? diff.current_vrl === diff.upstream_vrl : true;

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle>Upstream Parser Changes</DialogTitle>
          <DialogDescription>
            {diff?.file_path && (
              <span className="font-mono text-xs">{diff.file_path}</span>
            )}
          </DialogDescription>
        </DialogHeader>

        {!diffAccess.allowed ? (
          <div className="py-8 text-center text-sm text-muted-foreground">
            {diffAccess.reason}
          </div>
        ) : appliedNeedsDeploy ? (
          <div className="py-6 space-y-4">
            <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl flex items-start gap-3">
              <Rocket className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
              <div className="text-sm">
                <p className="font-medium text-amber-700 dark:text-amber-400">Parser updated — deploy to apply changes</p>
                <p className="text-amber-600/90 dark:text-amber-400/80 mt-1">
                  The VRL has been saved but the pipeline is still running the previous version. Deploy now to push changes to Vector, or deploy later from the source detail page.
                </p>
              </div>
            </div>
          </div>
        ) : isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
          </div>
        ) : diff ? (
          <div className="overflow-y-auto flex-1 min-h-0 space-y-4">
            {/* Summary */}
            <div className="flex items-center gap-4 text-sm flex-wrap">
              {vrlMatch ? (
                <Badge variant="outline" className="text-green-600 border-green-600">
                  <Check className="w-3 h-3 mr-1" />
                  VRL matches
                </Badge>
              ) : (
                <Badge variant="outline" className="text-amber-600 border-amber-600">
                  VRL changed
                </Badge>
              )}
              {diff.upstream_version && (
                <Badge variant="outline">
                  v{diff.upstream_version}
                </Badge>
              )}
              {diff.upstream_display_name && (
                <span className="text-sm text-muted-foreground">
                  {diff.upstream_display_name}
                </span>
              )}
            </div>

            {/* Diff view */}
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <h4 className="text-sm font-medium">VRL Changes</h4>
                <span className="text-xs text-muted-foreground">
                  (Your version → Upstream version)
                </span>
              </div>
              <DiffViewer
                oldText={diff.current_vrl}
                newText={diff.upstream_vrl}
              />
            </div>
          </div>
        ) : (
          <div className="text-center py-8 text-muted-foreground">
            Failed to load diff
          </div>
        )}

        <DialogFooter className="flex-shrink-0">
          {!diffAccess.allowed ? (
            <Button variant="outline" onClick={() => handleClose(false)}>
              Close
            </Button>
          ) : appliedNeedsDeploy ? (
            <>
              <Button
                variant="outline"
                onClick={() => {
                  navigate(`/ingestion/log-sources/${logSourceId}`);
                  handleClose(false);
                }}
              >
                Go to Source
              </Button>
              <PermissionAction access={deployAccess}>
                <Button
                  onClick={handleDeployNow}
                  disabled={deploying || !deployAccess.allowed}
                >
                  {deploying ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Rocket className="w-4 h-4 mr-2" />
                  )}
                  Deploy Now
                </Button>
              </PermissionAction>
            </>
          ) : (
            <>
              <Button variant="outline" onClick={() => handleClose(false)}>
                Close
              </Button>
              <PermissionAction access={dismissAccess}>
                <Button
                  variant="ghost"
                  onClick={() => dismissMutation.mutate()}
                  disabled={
                    dismissMutation.isPending ||
                    applyMutation.isPending ||
                    !dismissAccess.allowed
                  }
                >
                  {dismissMutation.isPending ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <X className="w-4 h-4 mr-2" />
                  )}
                  Dismiss
                </Button>
              </PermissionAction>
              <PermissionAction access={applyAccess}>
                <Button
                  onClick={() => applyMutation.mutate()}
                  disabled={
                    applyMutation.isPending ||
                    dismissMutation.isPending ||
                    vrlMatch ||
                    !applyAccess.allowed
                  }
                >
                  {applyMutation.isPending ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <ArrowUpCircle className="w-4 h-4 mr-2" />
                  )}
                  Apply Update
                </Button>
              </PermissionAction>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
