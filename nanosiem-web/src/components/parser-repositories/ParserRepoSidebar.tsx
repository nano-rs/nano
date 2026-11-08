// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-526 — left-rail repo list. Port of design-ref/shadcn/log-repos-sidebar.jsx.
// NAN-532 — custom-repo connect affordances hidden; only the bundled
// nano-sh/parsers library is supported in the current ship.

import { Clock, RefreshCw, AlertTriangle, Trash2 } from 'lucide-react';
import { SiGithub } from '@icons-pack/react-simple-icons';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { ParserRepoView } from './helpers';

interface SidebarProps {
  repos: ParserRepoView[];
  activeRepoId: string | null;
  onActivate: (id: string) => void;
  onSyncNow: (id: string) => void;
  onOpenHistory: (id: string) => void;
  onDelete: (id: string) => void;
  syncingId: string | null;
}

export function ParserRepoSidebar({
  repos,
  activeRepoId,
  onActivate,
  onSyncNow,
  onOpenHistory,
  onDelete,
  syncingId,
}: SidebarProps) {
  return (
    <div className="flex flex-col h-full min-h-0 border-r border-border bg-card/30">
      {/* Header */}
      <div className="flex items-center justify-between px-3.5 h-[46px] border-b border-border shrink-0">
        <div className="flex items-baseline gap-1.5">
          <div className="text-[13px] font-semibold text-foreground">Libraries</div>
          <div className="text-[10.5px] font-mono text-muted-foreground tabular-nums">
            {repos.length}
          </div>
        </div>
      </div>

      {/* Repo list */}
      <div className="flex-1 overflow-auto p-2 flex flex-col gap-1.5">
        {repos.map((r) => (
          <RepoCard
            key={r.id}
            repo={r}
            active={activeRepoId === r.id}
            syncing={syncingId === r.id}
            onActivate={() => onActivate(r.id)}
            onSyncNow={() => onSyncNow(r.id)}
            onOpenHistory={() => onOpenHistory(r.id)}
            onDelete={() => onDelete(r.id)}
          />
        ))}
      </div>

      {/* Footer */}
      <div className="border-t border-border px-3 py-2 shrink-0 flex items-center gap-2 text-[10.5px] text-muted-foreground font-mono">
        <span className="w-1.5 h-1.5 rounded-full bg-success" />
        <span>registry online</span>
      </div>
    </div>
  );
}

interface RepoCardProps {
  repo: ParserRepoView;
  active: boolean;
  syncing: boolean;
  onActivate: () => void;
  onSyncNow: () => void;
  onOpenHistory: () => void;
  onDelete: () => void;
}

function RepoCard({
  repo,
  active,
  syncing,
  onActivate,
  onSyncNow,
  onOpenHistory,
  onDelete,
}: RepoCardProps) {
  const pendingBadge = repo.counts.needsUpdate > 0;

  return (
    <div
      onClick={onActivate}
      className={cn(
        'relative group rounded-lg border px-3 pt-2.5 pb-2 cursor-pointer transition',
        active
          ? 'border-primary/40 bg-primary/5'
          : 'border-border bg-card hover:border-border/80 hover:bg-muted/40',
      )}
    >
      {/* Top row: icon + slug */}
      <div className="flex items-start gap-2">
        <div className="w-[26px] h-[26px] rounded-md border border-border bg-background flex items-center justify-center shrink-0 mt-[1px]">
          <SiGithub className="w-[13px] h-[13px] text-foreground/70" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5">
            <div className="text-[11px] text-muted-foreground truncate">{repo.org}</div>
          </div>
          <div className="text-[12.5px] font-medium text-foreground leading-tight flex items-center gap-1.5 min-w-0">
            <span className="truncate font-mono">{repo.name}</span>
            {repo.builtin && (
              <span className="shrink-0 text-[9px] font-mono uppercase tracking-wider text-primary border border-primary/40 bg-primary/5 rounded px-1 py-px">
                nano
              </span>
            )}
            {repo.visibility === 'private' && (
              <span className="shrink-0 text-[9px] font-mono uppercase tracking-wider text-muted-foreground border border-border rounded px-1 py-px">
                priv
              </span>
            )}
          </div>
        </div>
        {/* Per-card delete (hover) */}
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onDelete();
              }}
              className="w-[20px] h-[20px] rounded-md flex items-center justify-center text-muted-foreground hover:text-destructive hover:bg-destructive/5 opacity-0 group-hover:opacity-100 transition-opacity"
              aria-label="Remove repository"
            >
              <Trash2 className="w-[11px] h-[11px]" strokeWidth={1.5} />
            </button>
          </TooltipTrigger>
          <TooltipContent>Remove repository</TooltipContent>
        </Tooltip>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-4 gap-1 mt-2.5">
        <Stat v={repo.total} label="total" />
        <Stat v={repo.counts.imported} label="used" tone="good" />
        <Stat
          v={repo.counts.needsUpdate}
          label="upd"
          tone={repo.counts.needsUpdate > 0 ? 'warn' : 'muted'}
        />
        <Stat
          v={repo.counts.drift}
          label="drift"
          tone={repo.counts.drift > 0 ? 'danger' : 'muted'}
        />
      </div>

      {/* Sync row */}
      <div className="mt-2.5 pt-2 border-t border-border flex items-center gap-2">
        <div className="flex-1 min-w-0 text-[10px] text-muted-foreground font-mono leading-tight">
          <div className="flex items-center gap-1">
            <span
              className={cn(
                'w-1 h-1 rounded-full',
                repo.lastSync.result === 'failed' ? 'bg-destructive' : 'bg-success',
              )}
            />
            synced {repo.lastSync.relative}
          </div>
          {repo.autoSync !== 'off' ? (
            <div className="truncate">
              next in {repo.nextSync.in} · {repo.nextSync.cadence}
            </div>
          ) : (
            <div className="truncate">manual sync</div>
          )}
        </div>
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onOpenHistory();
              }}
              className="w-[22px] h-[22px] rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5"
              aria-label="Sync history"
            >
              <Clock className="w-[12px] h-[12px]" strokeWidth={1.5} />
            </button>
          </TooltipTrigger>
          <TooltipContent>Sync history</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onSyncNow();
              }}
              disabled={syncing}
              className={cn(
                'h-[22px] px-2 rounded-md flex items-center gap-1 text-[10px] font-medium border transition',
                syncing
                  ? 'border-border bg-foreground/5 text-muted-foreground cursor-not-allowed'
                  : 'border-border bg-card hover:bg-muted text-foreground/70 hover:text-foreground',
              )}
            >
              <RefreshCw
                className={cn('w-[11px] h-[11px]', syncing && 'animate-spin')}
                strokeWidth={1.5}
              />
              {syncing ? 'Syncing' : 'Sync'}
            </button>
          </TooltipTrigger>
          <TooltipContent>{syncing ? 'Syncing…' : 'Sync now'}</TooltipContent>
        </Tooltip>
      </div>

      {/* Needs-update banner */}
      {pendingBadge && !syncing && (
        <div className="mt-2 rounded-md px-2 py-1 flex items-center gap-1.5 text-[10.5px] text-warning bg-warning/10">
          <AlertTriangle className="w-[11px] h-[11px]" strokeWidth={2} />
          {repo.counts.needsUpdate} {repo.counts.needsUpdate === 1 ? 'parser has' : 'parsers have'} updates
        </div>
      )}
    </div>
  );
}

function Stat({
  v,
  label,
  tone = 'muted',
}: {
  v: number;
  label: string;
  tone?: 'good' | 'warn' | 'danger' | 'muted';
}) {
  const color = {
    good: 'var(--color-success)',
    warn: 'var(--color-warning)',
    danger: 'var(--color-destructive)',
    muted: 'var(--color-foreground)',
  }[tone];
  return (
    <div className="flex flex-col items-start">
      <div
        className="text-[12.5px] font-mono font-semibold tabular-nums leading-none"
        style={{ color }}
      >
        {v}
      </div>
      <div className="text-[9px] uppercase tracking-wider text-muted-foreground mt-[3px]">
        {label}
      </div>
    </div>
  );
}
