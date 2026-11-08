// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { Plus, RefreshCw, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { formatUTC, formatUTCShort } from '@/lib/date-utils';
import { PipelineLoading, PipelineNotice, PipelinePageHeader, PipelineStateBadge } from './PipelineCommon';
import type { PipelineListProps } from './types';
import { cn } from '@/lib/utils';

type Filter = 'all' | 'drafts' | 'steps' | 'vrl';
const FILTER_LABELS: Record<Filter, string> = { all: 'All', drafts: 'Unpublished drafts', steps: 'Step plans', vrl: 'Plain VRL' };

export function PipelineList({ pipelines, loading, error, canCreate, onCreate, onOpen, onRetry }: PipelineListProps) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const rows = pipelines.filter((pipeline) => {
    if (filter === 'drafts' && !pipeline.hasDraft) return false;
    if (filter === 'steps' && !pipeline.stepPlan) return false;
    if (filter === 'vrl' && pipeline.stepPlan) return false;
    return `${pipeline.name} ${pipeline.description} ${pipeline.sourceType} ${pipeline.id}`.toLowerCase().includes(query.toLowerCase());
  });
  return (
    <section className="flex h-full min-h-0 flex-col text-foreground">
      <PipelinePageHeader
        title="Pipelines"
        meta={
          <>
            <span>{pipelines.length} sources</span>
            <span>{pipelines.filter((pipeline) => pipeline.stepPlan).length} step plans</span>
            <span>{pipelines.filter((pipeline) => pipeline.hasDraft).length} unpublished drafts</span>
          </>
        }
        actions={
          <Button onClick={onCreate} disabled={!canCreate}>
            <Plus className="h-3.5 w-3.5" strokeWidth={1.5} />
            Add source
          </Button>
        }
      />
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border px-4 py-2">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" strokeWidth={1.5} />
          <Input
            aria-label="Search pipelines"
            className="h-7 w-[300px] max-w-full pl-8 text-[12px]"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search name, source type, id…"
          />
        </div>
        <div className="flex items-center gap-0.5 rounded-md border border-border p-0.5" aria-label="Pipeline filters">
          {(Object.keys(FILTER_LABELS) as Filter[]).map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={filter === value}
              onClick={() => setFilter(value)}
              className={cn('h-[22px] rounded-sm px-2 text-[11px] font-medium', filter === value ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:bg-accent')}
            >
              {FILTER_LABELS[value]}
            </button>
          ))}
        </div>
        <Button className="ml-auto h-7 w-7" variant="outline" size="icon" aria-label="Refresh pipelines" onClick={onRetry} disabled={loading}>
          <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} strokeWidth={1.5} />
        </Button>
      </div>
      {error ? (
        <div className="p-4">
          <PipelineNotice title="Pipelines could not be loaded" tone="error">{error}</PipelineNotice>
          <Button variant="outline" className="mt-3" onClick={onRetry}>Retry</Button>
        </div>
      ) : loading ? (
        <PipelineLoading />
      ) : pipelines.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2 px-4 py-16 text-center">
          <p className="text-[13px] font-medium">No log sources yet</p>
          <p className="max-w-md text-[11.5px] text-muted-foreground">
            Every log source has a pipeline: its parser as ordered steps. Onboard a source to start.
          </p>
          {canCreate && <Button className="mt-2" onClick={onCreate}>Add source</Button>}
        </div>
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="w-full min-w-[760px] table-fixed text-left text-[12px]">
            <thead className="sticky top-0 z-10 bg-background">
              <tr className="h-7 border-b border-border font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="w-[30%] pl-4 font-medium">Source</th>
                <th className="w-[14%] px-2 font-medium">Type</th>
                <th className="w-[13%] px-2 font-medium">Processing</th>
                <th className="w-[12%] px-2 font-medium">State</th>
                <th className="w-[10%] px-2 font-medium">Draft</th>
                <th className="w-[15%] px-2 font-medium">Last deployed</th>
                <th className="w-[6%]"><span className="sr-only">Open</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((pipeline, index) => (
                <tr
                  key={pipeline.id}
                  tabIndex={0}
                  onClick={() => onOpen(pipeline.id)}
                  onKeyDown={(event) => {
                    if (event.target !== event.currentTarget) return;
                    if (event.key === 'Enter') onOpen(pipeline.id);
                    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                      event.preventDefault();
                      const next = event.currentTarget.parentElement?.children[index + (event.key === 'ArrowDown' ? 1 : -1)] as HTMLElement | undefined;
                      next?.focus();
                    }
                  }}
                  className="h-7 cursor-pointer border-b border-border outline-none hover:bg-accent/50 focus-visible:bg-primary/5 focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring"
                >
                  <td className="py-1 pl-4 pr-2">
                    <span className="block truncate text-[12px] font-medium" title={pipeline.description ? `${pipeline.description} · ${pipeline.id}` : pipeline.id}>{pipeline.name}</span>
                  </td>
                  <td className="truncate px-2 font-mono text-[10.5px]">{pipeline.sourceType}</td>
                  <td className="px-2 font-mono text-[10.5px]">
                    {pipeline.stepPlan ? <span>{pipeline.stepCount} step{pipeline.stepCount === 1 ? '' : 's'}</span> : <span className="text-muted-foreground">plain VRL</span>}
                  </td>
                  <td className="px-2">
                    <PipelineStateBadge state={!pipeline.enabled ? 'disabled' : pipeline.deployed ? 'live' : 'not_deployed'} />
                  </td>
                  <td className="px-2 font-mono text-[10.5px] text-muted-foreground">
                    {pipeline.hasDraft ? <span className="text-foreground">edit {pipeline.draftRevision}</span> : 'none'}
                  </td>
                  <td className="px-2 font-mono text-[10.5px] text-muted-foreground">
                    {pipeline.deployedAt ? <time dateTime={pipeline.deployedAt} title={formatUTC(pipeline.deployedAt)}>{formatUTCShort(pipeline.deployedAt)}</time> : '—'}
                  </td>
                  <td className="pr-2">
                    <Button
                      variant="ghost"
                      className="h-6 px-1.5 text-[11px]"
                      aria-label={`Open ${pipeline.name}`}
                      onClick={(event) => { event.stopPropagation(); onOpen(pipeline.id); }}
                    >
                      Open
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && (
            <div className="p-10 text-center text-[11.5px] text-muted-foreground">
              No pipelines match this search and filter.
              <Button variant="link" className="ml-1 h-6 text-[11.5px]" onClick={() => { setQuery(''); setFilter('all'); }}>Clear filters</Button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
