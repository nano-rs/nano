// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { Plus, RefreshCw, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  PipelineLoading,
  PipelineNotice,
  PipelinePageHeader,
  PipelineStateBadge,
} from './PipelineCommon';
import type { PipelineListProps } from './types';
import { pipeInputTotal, type PipeLaneInputCounts } from '@/lib/api/pipelines';
import { cn } from '@/lib/utils';

export function PipelineList({
  pipelines,
  loading,
  error,
  canCreate,
  onCreate,
  onOpen,
  onRetry,
  inputCounts,
}: PipelineListProps) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<'all' | 'drafts' | 'attention'>('all');
  const rows = pipelines.filter((pipeline) => {
    if (filter === 'drafts' && !pipeline.hasDraft) return false;
    if (
      filter === 'attention' &&
      pipeline.health === 'healthy' &&
      !['failed', 'rejected'].includes(pipeline.latestRelease?.state ?? '')
    )
      return false;
    return `${pipeline.name} ${pipeline.description} ${pipeline.sourceName} ${pipeline.sourceType}`
      .toLowerCase()
      .includes(query.toLowerCase());
  });
  return (
    <section className="flex h-full min-h-0 flex-col text-foreground">
      <PipelinePageHeader
        title="Pipelines"
        meta={
          <>
            <span>{pipelines.length} pipelines</span>
            <span>
              {pipelines.filter((pipeline) => pipeline.hasDraft).length} drafts
            </span>
            <span>Nano shared lake · managed Vector</span>
          </>
        }
        actions={
          <Button onClick={onCreate} disabled={!canCreate}>
            <Plus className="h-3.5 w-3.5" strokeWidth={1.5} />
            Add source
          </Button>
        }
      />
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border bg-card/40 px-4 py-2.5">
        <div className="relative">
          <Search
            className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            strokeWidth={1.5}
          />
          <Input
            aria-label="Search pipelines"
            className="w-[300px] max-w-full pl-8"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search name, source, type…"
          />
        </div>
        <div
          className="flex items-center gap-0.5 rounded-md border border-border bg-card p-0.5"
          aria-label="Pipeline filters"
        >
          {(['all', 'drafts', 'attention'] as const).map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={filter === value}
              onClick={() => setFilter(value)}
              className={cn(
                'h-[26px] rounded-sm px-2.5 text-[11px] font-medium',
                filter === value
                  ? 'bg-primary/15 text-primary'
                  : 'text-muted-foreground hover:bg-accent'
              )}
            >
              {value === 'attention'
                ? 'Needs attention'
                : value === 'drafts'
                  ? 'Drafts'
                  : 'All'}
            </button>
          ))}
        </div>
        <Button
          className="ml-auto"
          variant="outline"
          size="icon"
          aria-label="Refresh pipelines"
          onClick={onRetry}
          disabled={loading}
        >
          <RefreshCw
            className={cn('h-3.5 w-3.5', loading && 'animate-spin')}
            strokeWidth={1.5}
          />
        </Button>
      </div>
      {error ? (
        <div className="p-4">
          <PipelineNotice title="Pipelines could not be loaded" tone="error">
            {error}
          </PipelineNotice>
          <Button variant="outline" className="mt-3" onClick={onRetry}>
            Retry
          </Button>
        </div>
      ) : loading ? (
        <PipelineLoading />
      ) : pipelines.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2 px-4 py-16 text-center">
          <p className="text-[13px] font-medium">No pipelines yet</p>
          <p className="max-w-md text-[11.5px] text-muted-foreground">
            Onboard a source to manage its processing before events reach Nano
            Lake.
          </p>
          {canCreate && (
            <Button className="mt-2" onClick={onCreate}>
              Add source
            </Button>
          )}
        </div>
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="w-full min-w-[820px] table-fixed text-left text-[12px]">
            <thead className="sticky top-0 z-10 bg-background">
              <tr className="h-7 border-b border-border font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="w-[25%] pl-4 font-medium">Name</th>
                <th className="w-[17%] px-2 font-medium">Source</th>
                <th className="w-[8%] px-2 font-medium">Inputs</th>
                <th className="w-[12%] px-2 font-medium">Health</th>
                <th className="w-[8%] px-2 font-medium">Active</th>
                <th className="w-[9%] px-2 font-medium">Draft</th>
                <th className="w-[16%] px-2 font-medium">Latest release</th>
                <th className="w-[5%]">
                  <span className="sr-only">Open</span>
                </th>
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
                      const next = event.currentTarget.parentElement?.children[
                        index + (event.key === 'ArrowDown' ? 1 : -1)
                      ] as HTMLElement | undefined;
                      next?.focus();
                    }
                  }}
                  className="h-11 cursor-pointer border-b border-border outline-none hover:bg-accent/50 focus-visible:bg-primary/5 focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring"
                >
                  <td className="py-2 pl-4 pr-2">
                    <span className="block truncate text-[12.5px] font-medium">
                      {pipeline.name}
                    </span>
                    <span className="block truncate text-[10.5px] text-muted-foreground">
                      {pipeline.description || pipeline.id}
                    </span>
                  </td>
                  <td className="px-2">
                    <span className="block truncate font-mono text-[10.5px]">
                      {pipeline.sourceName}
                    </span>
                    <span className="font-mono text-[10px] text-muted-foreground">
                      {pipeline.sourceType}
                    </span>
                  </td>
                  <td className="px-2 font-mono text-[11px]">
                    <PipelineInputCount counts={inputCounts?.[pipeline.sourceId]} />
                  </td>
                  <td className="px-2">
                    <PipelineStateBadge state={pipeline.health} />
                  </td>
                  <td className="px-2 font-mono text-[11px]">
                    {pipeline.activeRevision === null
                      ? '—'
                      : `v${pipeline.activeRevision}`}
                  </td>
                  <td className="px-2 font-mono text-[11px] text-muted-foreground">
                    {pipeline.hasDraft
                      ? `edit ${pipeline.draftRevision}`
                      : 'None'}
                  </td>
                  <td className="px-2">
                    {pipeline.latestRelease ? (
                      <PipelineStateBadge
                        state={pipeline.latestRelease.state}
                      />
                    ) : (
                      <span className="text-[10.5px] text-muted-foreground">
                        No observed release
                      </span>
                    )}
                  </td>
                  <td className="pr-2">
                    <Button
                      variant="ghost"
                      className="h-6 px-1.5 text-[11px]"
                      aria-label={`Open ${pipeline.name}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        onOpen(pipeline.id);
                      }}
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
              <Button
                variant="link"
                className="ml-1 h-6 text-[11.5px]"
                onClick={() => {
                  setQuery('');
                  setFilter('all');
                }}
              >
                Clear filters
              </Button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function PipelineInputCount({ counts }: { counts: PipeLaneInputCounts | undefined }) {
  if (!counts) return <span className="text-muted-foreground">—</span>;
  const total = pipeInputTotal(counts);
  const title = `${counts.push} push · ${counts.pull} pull · ${counts.connectors} connector`;
  return (
    <span title={title} aria-label={`${total} inputs: ${title}`} data-testid={`pipeline-inputs-${counts.log_source_id}`}>
      {total}
      {counts.pull > 0 && (
        <span className="ml-1 text-[10px] text-muted-foreground">{counts.pull} pull</span>
      )}
    </span>
  );
}
