// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, useEffect } from 'react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Loader2,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  CircleCheck,
  Copy,
  XCircle,
} from 'lucide-react';
import { api } from '@/lib/api';
import type { AiFailure, AiFailureStats, AiAgentType } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDistanceToNow } from 'date-fns';

const AGENT_TYPES: { value: AiAgentType | 'all'; label: string }[] = [
  { value: 'all', label: 'All Agents' },
  { value: 'query', label: 'Query Agent' },
  { value: 'dashboard', label: 'Dashboard Agent' },
  { value: 'detection', label: 'Detection Agent' },
  { value: 'parser', label: 'Parser Agent' },
  { value: 'summarize', label: 'Summarize Agent' },
];

const PAGE_SIZE = 20;

function getAgentBadgeColor(agentType: string): string {
  switch (agentType) {
    case 'query': return 'bg-primary/10 text-primary';
    case 'dashboard': return 'bg-purple-500/10 text-purple-400';
    case 'detection': return 'bg-orange-500/10 text-orange-400';
    case 'parser': return 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400';
    case 'summarize': return 'bg-cyan-500/10 text-cyan-400';
    default: return 'bg-gray-500/10 text-muted-foreground';
  }
}

export function DebugSettings() {
  useDocumentTitle('AI Debug');

  const { toast } = useToast();
  const [loading, setLoading] = useState(true);
  const [failures, setFailures] = useState<AiFailure[]>([]);
  const [stats, setStats] = useState<AiFailureStats[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [page, setPage] = useState(0);
  const [agentFilter, setAgentFilter] = useState<AiAgentType | 'all'>('all');
  const [selectedFailure, setSelectedFailure] = useState<AiFailure | null>(null);

  const fetchFailures = async () => {
    setLoading(true);
    try {
      const response = await api.getAiFailures({
        agent_type: agentFilter === 'all' ? undefined : agentFilter,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      });
      setFailures(response.failures);
      setStats(response.stats);
      setTotalCount(response.total_count);
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to fetch AI failures',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFailures();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, agentFilter]);

  const totalPages = Math.ceil(totalCount / PAGE_SIZE);
  const offset = page * PAGE_SIZE;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: 'Copied',
      description: 'Text copied to clipboard',
    });
  };

  if (loading && failures.length === 0) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="px-6 py-5 space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-semibold tracking-tight text-foreground">AI Debug</h1>
          <p className="text-[11.5px] text-muted-foreground mt-0.5">View AI query generation failures for debugging and improvement</p>
        </div>
        <Button
          onClick={fetchFailures}
          variant="outline"
          disabled={loading}
          className="h-8 text-[11.5px] gap-1.5 border-border"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {stats.length > 0 ? (
          stats.map((stat) => (
            <div key={stat.agent_type} className="rounded-lg border border-border bg-card px-3 py-3">
              <p className="font-mono text-[10px] text-muted-foreground uppercase tracking-wide capitalize">{stat.agent_type} Agent</p>
              <div className="flex items-baseline justify-between mt-1">
                <span className="font-mono text-[20px] font-bold text-foreground leading-none">{stat.total_failures}</span>
                <span className="font-mono text-[10px] text-muted-foreground">{stat.resolved_count} resolved</span>
              </div>
              <p className="font-mono text-[10px] text-muted-foreground mt-1">avg {stat.avg_retries.toFixed(1)} retries</p>
            </div>
          ))
        ) : (
          <div className="col-span-full rounded-lg border border-border bg-card py-8 text-center">
            <CircleCheck className="h-8 w-8 mx-auto mb-2 text-emerald-500/50" />
            <p className="text-[12.5px] text-muted-foreground">No AI failures recorded</p>
          </div>
        )}
      </div>

      {/* Failure log */}
      <div className="rounded-lg border border-border overflow-hidden">
        <div className="border-b border-border px-3 py-3 flex items-center justify-between bg-card/50">
          <div>
            <span className="text-[13px] font-semibold text-foreground">Failure Log</span>
            <span className="font-mono text-[11px] text-muted-foreground ml-2 tabular-nums">{totalCount} total</span>
          </div>
          <Select
            value={agentFilter}
            onValueChange={(v) => {
              setAgentFilter(v as AiAgentType | 'all');
              setPage(0);
            }}
          >
            <SelectTrigger className="w-40 h-8 text-[12px] border-border">
              <SelectValue placeholder="Filter by agent" />
            </SelectTrigger>
            <SelectContent>
              {AGENT_TYPES.map((type) => (
                <SelectItem key={type.value} value={type.value} className="text-[12px]">
                  {type.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          {loading ? (
            <div className="flex items-center justify-center py-10">
              <Loader2 className="w-6 h-6 animate-spin text-primary" />
            </div>
          ) : (
            <>
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border/60">
                    <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground w-28">Agent</th>
                    <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">User Request</th>
                    <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Error</th>
                    <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground w-16">Retries</th>
                    <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground w-10"></th>
                    <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground w-28">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {failures.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="text-center text-[12px] text-muted-foreground py-10">
                        No failures found
                      </td>
                    </tr>
                  ) : (
                    failures.map((failure) => (
                      <tr
                        key={failure.id}
                        className="hover:bg-foreground/[0.025] cursor-pointer transition-colors"
                        onClick={() => setSelectedFailure(failure)}
                      >
                        <td className="px-3 py-2">
                          <span className={`font-mono text-[9.5px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded ${getAgentBadgeColor(failure.agent_type)}`}>
                            {failure.agent_type}
                          </span>
                        </td>
                        <td className="px-3 py-2 max-w-[200px] truncate text-[11.5px] text-foreground">
                          {failure.user_request}
                        </td>
                        <td className="px-3 py-2 max-w-[180px] truncate text-[11.5px] text-red-400">
                          {failure.error_message}
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground tabular-nums">{failure.retry_count}</td>
                        <td className="px-3 py-2">
                          {failure.was_resolved ? (
                            <CircleCheck className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <XCircle className="w-3.5 h-3.5 text-red-400" />
                          )}
                        </td>
                        <td className="px-3 py-2 font-mono text-[10.5px] text-muted-foreground">
                          {formatDistanceToNow(new Date(failure.created_at), { addSuffix: true })}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between px-3 py-2 border-t border-border bg-card/30">
                  <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
                    {offset + 1}–{Math.min(offset + PAGE_SIZE, totalCount)} of {totalCount}
                  </span>
                  <div className="flex items-center gap-1">
                    <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="h-7 w-7 p-0 border-border">
                      <ChevronLeft className="w-3.5 h-3.5" />
                    </Button>
                    <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums px-2">{page + 1}/{totalPages}</span>
                    <Button variant="outline" size="sm" onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="h-7 w-7 p-0 border-border">
                      <ChevronRight className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Detail Dialog */}
      <Dialog open={!!selectedFailure} onOpenChange={() => setSelectedFailure(null)}>
        <DialogContent className="bg-card border-border max-w-3xl max-h-[80vh] overflow-y-auto gap-0 p-0">
          <DialogHeader className="border-b border-border px-5 py-4">
            <DialogTitle className="text-[14px] font-semibold text-foreground flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-500" />
              AI Failure Details
              {selectedFailure && (
                <span className="font-mono text-[11px] text-muted-foreground ml-2 font-normal">
                  {formatDistanceToNow(new Date(selectedFailure.created_at), { addSuffix: true })}
                </span>
              )}
            </DialogTitle>
          </DialogHeader>
          {selectedFailure && (
            <div className="px-5 py-4 space-y-4">
              <div className="flex items-center gap-2">
                <span className={`font-mono text-[9.5px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded ${getAgentBadgeColor(selectedFailure.agent_type)}`}>
                  {selectedFailure.agent_type}
                </span>
                {selectedFailure.was_resolved ? (
                  <span className="font-mono text-[9.5px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400">
                    Resolved after {selectedFailure.retry_count} retries
                  </span>
                ) : (
                  <span className="font-mono text-[9.5px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">
                    Failed after {selectedFailure.retry_count} retries
                  </span>
                )}
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">User Request</label>
                  <Button variant="ghost" size="sm" onClick={() => copyToClipboard(selectedFailure.user_request)} className="h-6 px-2 text-muted-foreground hover:text-primary">
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
                <div className="bg-muted/20 p-3 rounded-md border border-border text-[11.5px] text-foreground">
                  {selectedFailure.user_request}
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Generated Query</label>
                  <Button variant="ghost" size="sm" onClick={() => copyToClipboard(selectedFailure.generated_query || '')} className="h-6 px-2 text-muted-foreground hover:text-primary">
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
                <pre className="bg-muted/20 p-3 rounded-md border border-border font-mono text-[10.5px] overflow-x-auto text-foreground">
                  {selectedFailure.generated_query}
                </pre>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-red-400">Error Message</label>
                  <Button variant="ghost" size="sm" onClick={() => copyToClipboard(selectedFailure.error_message)} className="h-6 px-2 text-muted-foreground hover:text-primary">
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
                <pre className="bg-red-500/10 border border-red-500/20 p-3 rounded-md font-mono text-[10.5px] overflow-x-auto text-red-400">
                  {selectedFailure.error_message}
                </pre>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
